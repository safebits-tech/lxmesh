__all__ = ['DHCPManager', 'DHCPState', 'DHCPSupervisor']

import contextlib
import errno
import logging
import math
import os
import select
import signal
import stat
import threading
import time
import typing

import pyroute2  # type: ignore[import-untyped]
import pyroute2.netlink  # type: ignore[import-untyped]

from lxmesh.dhcp.exceptions import DHCPError
from lxmesh.dhcp.io import FileReplacement
from lxmesh.dhcp.state import DHCPEventContext, DHCPInitialiseContext, DHCPLoadContext, DHCPOperationContext, DHCPSVI
from lxmesh.dhcp.state.host import HostState
from lxmesh.dhcp.state.svi import SVIState
from lxmesh.netlink.monitor import NetlinkMonitor
from lxmesh.state import StateManager, StateTable


class DHCPState(StateTable[DHCPEventContext, DHCPInitialiseContext, DHCPLoadContext, DHCPOperationContext]):
    SVI     = SVIState
    Host    = HostState


class DHCPSupervisor(threading.Thread):
    def __init__(self, *,
                 executable: str,
                 arguments: list[str],
                 restart_interval: float,
                 terminate_timeout: float):
        super().__init__(name="dhcp-supervisor")

        self.executable = executable
        self.arguments = arguments
        self.restart_interval = restart_interval
        self.terminate_timeout = terminate_timeout

        self.stopped = False
        self.rd_pipe, self.wr_pipe = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)

        self.poll = select.poll()

        self.server_wanted = False
        self.server_reload_wanted = False
        self.server_restart_wanted = False

    def wakeup(self) -> None:
        try:
            os.write(self.wr_pipe, b'\x00')
        except BlockingIOError:
            pass

    def start(self) -> None:
        if self.is_alive() or self.stopped:
            raise ValueError("cannot restart DHCP supervisor thread")
        super().start()

    def stop(self) -> None:
        if not self.stopped:
            self.stopped = True
            self.wakeup()

    def join(self, *args: typing.Any, **kw: typing.Any) -> None:
        if not self.stopped:
            raise ValueError("monitoring thread must be stopped before joining")
        super().join(*args, **kw)

    def server_start(self) -> None:
        if not self.server_wanted:
            self.server_wanted = True
            self.wakeup()

    def server_stop(self) -> None:
        if self.server_wanted:
            self.server_wanted = False
            self.wakeup()

    def server_reload(self) -> None:
        if not self.server_reload_wanted:
            self.server_reload_wanted = True
            self.wakeup()

    def server_restart(self) -> None:
        if not self.server_restart_wanted:
            self.server_wanted = True
            self.server_restart_wanted = True
            self.wakeup()

    def run(self) -> None:
        self.poll.register(self.rd_pipe, select.POLLIN)

        pid_fd:     int | None      = None
        server_pid: int | None      = None
        last_fail:  float | None    = None
        next_start: float           = float('inf')
        next_term:  float           = float('inf')
        next_kill:  float           = float('inf')
        while not self.stopped or server_pid is not None:
            now = time.monotonic()

            if self.stopped:
                self.server_wanted = False
                self.server_restart_wanted = False

            if self.server_restart_wanted:
                if server_pid is not None:
                    next_term = now
                self.server_restart_wanted = False

            if not self.server_wanted and server_pid is not None:
                if math.isinf(next_term) and math.isinf(next_kill):
                    next_term = now

            if self.server_reload_wanted:
                if server_pid is not None and math.isinf(next_term) and math.isinf(next_kill):
                    logging.info("Reloading DHCP server process '{}'.".format(server_pid))
                    try:
                        os.kill(server_pid, signal.SIGHUP)
                    except ProcessLookupError:
                        pass
                    except OSError as e:
                        logging.error("Failed to send SIGHUP to DHCP server: {} ({}).".format(os.strerror(e.errno), e.errno))
                    else:
                        logging.debug("Sent SIGHUP to DHCP server process '{}'.".format(server_pid))
                self.server_reload_wanted = False

            if now >= next_term:
                if server_pid is not None:
                    logging.info("Stopping DHCP server process '{}'.".format(server_pid))
                    try:
                        os.kill(server_pid, signal.SIGTERM)
                    except ProcessLookupError:
                        server_pid = None
                    except OSError as e:
                        logging.error("Failed to send SIGTERM to DHCP server: {} ({}).".format(os.strerror(e.errno), e.errno))
                        next_kill = now
                    else:
                        logging.debug("Sent SIGTERM to DHCP server process '{}'.".format(server_pid))
                        next_kill = now + self.terminate_timeout
                next_term = float('inf')

            if now >= next_kill:
                if server_pid is not None:
                    logging.warning("Killing unresponsive DHCP server process '{}'.".format(server_pid))
                    try:
                        os.kill(server_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        server_pid = None
                    except OSError as e:
                        logging.error("Failed to send SIGKILL to DHCP server: {} ({}).".format(os.strerror(e.errno), e.errno))
                        server_pid = None
                    else:
                        logging.debug("Sent SIGKILL to DHCP server process '{}'.".format(server_pid))
                next_kill = float('inf')

            if self.server_wanted and server_pid is None:
                if math.isinf(next_start):
                    if last_fail is not None:
                        next_start = max(last_fail + self.restart_interval, now)
                    else:
                        next_start = now

            if pid_fd is not None and server_pid is None:
                self.poll.unregister(pid_fd)
                os.close(pid_fd)
                pid_fd = None

            if now >= next_start:
                try:
                    server_pid = os.posix_spawnp(self.executable,
                                                 [self.executable] + self.arguments,
                                                 {})
                except OSError as e:
                    logging.error("Failed to spawn DHCP server: {} ({}).".format(os.strerror(e.errno), e.errno))
                    next_start = now + self.restart_interval
                else:
                    logging.info("Started DHCP server process '{}'.".format(server_pid))
                    next_start = float('inf')
                    try:
                        pid_fd = os.pidfd_open(server_pid)
                    except OSError as e:
                        logging.error("Failed to open pidfd for DHCP server: {} ({}).".format(os.strerror(e.errno), e.errno))
                    else:
                        if pid_fd is not None:  # Only included for mypy.
                            self.poll.register(pid_fd, select.POLLIN)

            timeout = min(next_start - now,
                          next_term - now,
                          next_kill - now)
            poll_result = self.poll.poll(max(timeout, 0) * 1000 if not math.isinf(timeout) else None)
            now = time.monotonic()
            for fd, fd_events in poll_result:
                if fd == pid_fd:
                    try:
                        wait_result = os.waitid(os.P_PIDFD, pid_fd, os.WEXITED | os.WNOHANG)
                    except OSError as e:
                        if e.errno == errno.EBADF:
                            self.poll.unregister(pid_fd)
                            os.close(pid_fd)
                            pid_fd = None
                            if server_pid is not None:
                                logging.warning("Lost ability to track DHCP server process (a zombie process may occur).")
                                server_pid = None
                            continue
                        logging.error("Failed to wait on DHCP server: {} ({}).".format(os.strerror(e.errno), e.errno))
                    else:
                        if wait_result is not None:
                            match wait_result.si_code:
                                case os.CLD_EXITED:
                                    if wait_result.si_status == 0:
                                        logging.info("DHCP Server exited cleanly.")
                                    else:
                                        logging.warning("DHCP Server exited with status code '{}'.".format(wait_result.si_status))
                                        last_fail = now
                                case os.CLD_KILLED | os.CLD_DUMPED:
                                    logging.warning("DHCP Server killed with signal '{}'".format(wait_result.si_status))
                                    last_fail = now
                            server_pid = None
                            next_term = float('inf')
                            next_kill = float('inf')
                elif fd == self.rd_pipe:
                    try:
                        os.read(self.rd_pipe, 4096)
                    except BlockingIOError:
                        pass


class DHCPManager(StateManager[DHCPEventContext, DHCPInitialiseContext, DHCPLoadContext, DHCPOperationContext], state_type=DHCPState):
    def __init__(self, *,
                 dhcp_supervisor: DHCPSupervisor | None,
                 netlink_monitor: NetlinkMonitor,
                 config_filepath: str | None,
                 hosts_filepath: str | None,
                 file_group: str | None,
                 ip4_lease_time: int,
                 ip6_lease_time: int) -> None:
        self.dhcp_supervisor = dhcp_supervisor
        self.config_filepath = config_filepath
        self.hosts_filepath = hosts_filepath
        self.file_group = file_group
        self.ip4_lease_time = ip4_lease_time
        self.ip6_lease_time = ip6_lease_time

        self.svi_map: dict[str, DHCPSVI] = {}

        init_context = DHCPInitialiseContext(manager=self,
                                             event_context_factory=self.event_context_factory,
                                             netlink_monitor=netlink_monitor)
        super().__init__(init_context=init_context)

    def event_context_factory(self) -> DHCPEventContext:
        return DHCPEventContext(manager=self,
                                active=self.active,
                                pending_add=self.pending_add,
                                pending_remove=self.pending_remove,
                                svi_map=self.svi_map,
                                ip4_lease_time=self.ip4_lease_time,
                                ip6_lease_time=self.ip6_lease_time)

    def register_svi(self, name: str) -> None:
        try:
            svi = self.svi_map[name]
        except KeyError:
            self.add(DHCPState.SVI(name=name))
            svi = self.svi_map[name] = DHCPSVI(refcount=0, name=name)
        svi.refcount += 1

    def unregister_svi(self, name: str) -> None:
        svi = self.svi_map[name]
        svi.refcount -= 1
        if svi.refcount == 0:
            self.remove(DHCPState.SVI(name=name))

    def reload(self) -> None:
        # With a flat-file database, a commit overwrites the entire data, so
        # there's no point in keeping track of what is stored.
        logging.debug("Reloading DHCP state.")

        with pyroute2.IPRoute() as ipr:
            context = DHCPLoadContext(manager=self,
                                      active=self.active,
                                      pending_add=self.pending_add,
                                      pending_remove=self.pending_remove,
                                      svi_map=self.svi_map,
                                      ip4_lease_time=self.ip4_lease_time,
                                      ip6_lease_time=self.ip6_lease_time,
                                      ipr=ipr)
            self.reload_objects(context)

        logging.debug("DHCP state: {} active, {} to add, {} to remove.".format(len(self.active), len(self.pending_add), len(self.pending_remove)))

    def commit(self) -> None:
        # If we don't have any active hosts or SVIs, we overwrite the
        # flat-files on each commit, even if it may not be necessary. This
        # is because no reload() is implemented, so without this behaviour,
        # if no hosts or SVIs are defined (i.e. there are no running LXD
        # instances), a file with contents would never be emptied. This
        # operation is however cheap, because we're not writing anything.

        logging.debug("Committing DHCP state.")

        with contextlib.ExitStack() as exit_stack, pyroute2.IPRoute() as ipr:
            if self.pending_add.len_by_type(DHCPState.SVI) == 0 and self.active.len_by_type(DHCPState.SVI) > 0:
                config_file = None
            elif self.config_filepath:
                while True:
                    try:
                        svi_obj = self.active.popitem_by_type(DHCPState.SVI)
                    except KeyError:
                        break
                    else:
                        self.pending_add.add(svi_obj)
                try:
                    config_file = FileReplacement(self.config_filepath, mode=stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP, group=self.file_group)
                except DHCPError as e:
                    logging.error("Failed to open config file: {}.".format(e))
                    config_file = None
                else:
                    exit_stack.push(config_file)
            else:
                config_file = None

            if self.pending_add.len_by_type(DHCPState.Host) == 0 and self.active.len_by_type(DHCPState.Host) > 0:
                hosts_file = None
            elif self.hosts_filepath:
                while True:
                    try:
                        host_obj = self.active.popitem_by_type(DHCPState.Host)
                    except KeyError:
                        break
                    else:
                        self.pending_add.add(host_obj)
                try:
                    hosts_file = FileReplacement(self.hosts_filepath, mode=stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP, group=self.file_group)
                except DHCPError as e:
                    logging.error("Failed to open hosts file: {}.".format(e))
                    hosts_file = None
                else:
                    exit_stack.push(hosts_file)
            else:
                hosts_file = None

            context = DHCPOperationContext(manager=self,
                                           svi_map=self.svi_map,
                                           ip4_lease_time=self.ip4_lease_time,
                                           ip6_lease_time=self.ip6_lease_time,
                                           ipr=ipr,
                                           config_file=config_file,
                                           hosts_file=hosts_file)
            self.commit_objects(context)

            if hosts_file is not None:
                try:
                    hosts_file.link()
                except DHCPError as e:
                    logging.error("Failed to link DHCP hosts file: {}.".format(e))
                else:
                    logging.info("Wrote DHCP hosts file '{}'.".format(self.hosts_filepath))

            if config_file is not None:
                try:
                    config_file.link()
                except DHCPError as e:
                    logging.error("Failed to link DHCP config file: {}.".format(e))
                else:
                    logging.info("Wrote DHCP config file '{}'.".format(self.config_filepath))
                    if self.dhcp_supervisor is not None:
                        if self.active.len_by_type(DHCPState.SVI) > 0:
                            self.dhcp_supervisor.server_restart()
                        else:
                            self.dhcp_supervisor.server_stop()
            elif self.dhcp_supervisor is not None:
                if self.active.len_by_type(DHCPState.SVI) > 0:
                    if hosts_file is not None:
                        self.dhcp_supervisor.server_reload()
                    self.dhcp_supervisor.server_start()
                else:
                    self.dhcp_supervisor.server_stop()
