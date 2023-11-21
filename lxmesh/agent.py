__all__ = ['LXMeshAgent']

import argparse
import contextlib
import enum
import itertools
import logging
import os
import pathlib
import queue
import random
import signal
import sys
import time
import types

import prctl  # type: ignore # No stubs.

from lxmesh.config import AgentConfig
from lxmesh.dhcp import DHCPManager, DHCPSupervisor
from lxmesh.exceptions import ApplicationError
from lxmesh.lxd import LXDEvent, LXDManager, LXDMonitor, LXDSVIConfig, TagsBase
from lxmesh.netlink import NetlinkManager, NetlinkSVIConfig
from lxmesh.netlink.monitor import NetlinkEvent, NetlinkMonitor


class Commands(enum.Enum):
    STOP = enum.auto()


class LXMeshAgent:
    @staticmethod
    def load_iproute_table_map() -> dict[str, int]:
        table_map: dict[str, int] = {}
        for filepath in itertools.chain([pathlib.Path('/etc/iproute2/rt_tables')],
                                        pathlib.Path('/etc/iproute2/rt_tables.d/').glob('*.conf')):
            try:
                with filepath.open() as file:
                    for line in file:
                        line = line.strip()
                        if line.startswith('#'):
                            continue
                        try:
                            table_number_str, table_name = line.split(None, 1)
                            table_number = int(table_number_str)
                        except ValueError:
                            continue
                        table_map[table_name] = table_number
            except OSError as e:
                logging.warning("Failed to read iproute2 table mapping file '{}': {} ({}).".format(filepath, os.strerror(e.errno), e.errno))
        return table_map

    @classmethod
    def is_deployed(cls) -> bool:
        if sys.argv[0]:
            exec_path = pathlib.Path(os.path.abspath(os.path.normpath(sys.argv[0])))
        else:
            exec_path = pathlib.Path(sys.executable)

        return exec_path.is_relative_to(pathlib.Path('/usr'))

    @classmethod
    def vardata_path(cls, *comps: str) -> str:
        if cls.is_deployed():
            return os.path.join('/var/lib/lxmesh', *comps)
        else:
            os.makedirs('./tmp-data', exist_ok=True)
            return os.path.join('./tmp-data', *comps)

    @classmethod
    def init_logging(cls, *,
                     level: int = logging.INFO,
                     systemd: bool = False,
                     stream: bool = False,
                     format_string: str = '%(levelname)s: %(message)s') -> None:
        if not cls.is_deployed():
            format_string = '%(asctime)s ' + format_string
        formatter = logging.Formatter(format_string)
        logger = logging.getLogger()
        logger.setLevel(level)
        if systemd:
            from systemd.journal import JournalHandler  # type: ignore # No stubs.
            handler = JournalHandler(SYSLOG_IDENTIFIER='lxmesh')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        if stream:
            handler = logging.StreamHandler(sys.stderr if stream is True else stream)
            handler.setFormatter(formatter)
            logger.addHandler(handler)

    def run(self) -> None:
        parser = argparse.ArgumentParser()
        parser.add_argument('-c', '--config', help="Configuration file to load.")
        parser.add_argument('-d', '--debug', action='store_true', default=False, help="Enable debug-level logging.")
        parser.add_argument('--systemd', action='store_true', default=False, help="Run as a System D service.")
        args = parser.parse_args()

        # FIXME
        logger = logging.getLogger()
        for handler in logger.handlers:
            logger.removeHandler(handler)
        self.init_logging(level=logging.DEBUG if args.debug else logging.INFO,
                          systemd=args.systemd,
                          stream=not args.systemd,
                          format_string="%(levelname)s: %(message)s" if not args.systemd else "%(message)s")
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('websockets').setLevel(logging.WARNING)

        if not args.config:
            logging.critical("Configuration file is mandatory.")
            sys.exit(1)
        try:
            config = AgentConfig.from_file(args.config)
        except ApplicationError as e:
            logging.critical("Failed to load configuration file: {}.".format(e))
            sys.exit(1)
        except OSError as e:
            logging.critical("Failed to read configuration file: {}.".format(e))
            sys.exit(1)

        if config.general.ip4_all_nodes_address is not None and not config.general.ip4_all_nodes_address.is_multicast:
            logging.critical("IPv4 all-nodes address '{}' is not multicast.".format(config.general.ip4_all_nodes_address))
            sys.exit(1)
        if config.general.ip6_all_nodes_address is not None and not config.general.ip6_all_nodes_address.is_multicast:
            logging.critical("IPv6 all-nodes address '{}' is not multicast.".format(config.general.ip6_all_nodes_address))
            sys.exit(1)

        logging.getLogger().setLevel(config.general.log_level)

        # Build netlink SVI configuration.
        table_map = self.load_iproute_table_map()
        if not config.default_svi_config.host_routes:
            default_host_routes_table = None
        elif config.default_svi_config.host_routes_table is None:
            default_host_routes_table = 0
        else:
            try:
                default_host_routes_table = int(config.default_svi_config.host_routes_table)
            except ValueError:
                try:
                    default_host_routes_table = table_map[config.default_svi_config.host_routes_table]
                except KeyError:
                    logging.error("Unknown route table '{}' for default SVI configuration; defaulting to SVI VRF main table.".format(config.default_svi_config.host_routes_table))
                    default_host_routes_table = 0
        netlink_default_svi_config = NetlinkSVIConfig(multicast=config.default_svi_config.multicast or False,
                                                      host_routes_table=default_host_routes_table)
        netlink_svi_config: dict[str, NetlinkSVIConfig] = {}
        for svi_name, svi_config in config.svi_config.items():
            if svi_name is None:
                continue
            if svi_config.multicast is None:
                multicast = netlink_default_svi_config.multicast
            else:
                multicast = svi_config.multicast
            if svi_config.host_routes is False:
                host_routes_table = None
            elif svi_config.host_routes is None and not config.default_svi_config.host_routes:
                host_routes_table = None
            elif svi_config.host_routes_table is None:
                host_routes_table = default_host_routes_table
            else:
                try:
                    host_routes_table = int(svi_config.host_routes_table)
                except ValueError:
                    try:
                        host_routes_table = table_map[svi_config.host_routes_table]
                    except KeyError:
                        logging.error("Unknown route table '{}' for SVI '{}'; defaulting to SVI VRF main table.".format(svi_config.host_routes_table, svi_name))
                        host_routes_table = 0
            netlink_svi_config[svi_name] = NetlinkSVIConfig(multicast=multicast,
                                                            host_routes_table=host_routes_table)

        # Build LXD SVI configuration.
        lxd_default_svi_config = LXDSVIConfig(mark=config.default_svi_config.netfilter_mark or 0,
                                              host_routes=config.default_svi_config.host_routes or False)
        lxd_svi_config: dict[str, LXDSVIConfig] = {}
        for svi_name, svi_config in config.svi_config.items():
            if svi_name is None:
                continue
            if svi_config.netfilter_mark is None:
                mark = lxd_default_svi_config.mark
            else:
                mark = svi_config.netfilter_mark
            if svi_config.host_routes is None:
                host_routes = lxd_default_svi_config.host_routes
            else:
                host_routes = svi_config.host_routes
            lxd_svi_config[svi_name] = LXDSVIConfig(mark=mark,
                                                    host_routes=host_routes)

        agent_caps: list[int] = [prctl.CAP_NET_ADMIN]
        if config.dhcp.server.executable:
            dhcp_server_caps = [prctl.CAP_NET_ADMIN, prctl.CAP_NET_BIND_SERVICE, prctl.CAP_NET_RAW]
        else:
            dhcp_server_caps = []
        prctl.cap_effective.limit(*agent_caps)
        prctl.cap_inheritable.limit(*dhcp_server_caps)
        prctl.cap_permitted.limit(*agent_caps, *dhcp_server_caps)

        command_queue: queue.SimpleQueue[Commands | LXDEvent | NetlinkEvent] = queue.SimpleQueue()

        def sighandler(signum: int, frame: types.FrameType | None) -> None:
            command_queue.put(Commands.STOP)

        signal.signal(signal.SIGINT, sighandler)
        signal.signal(signal.SIGTERM, sighandler)

        logging.info("Ready.")
        with contextlib.ExitStack() as exit_stack:
            lxd_monitor = LXDMonitor(command_queue)
            if config.dhcp.server.executable is not None:
                dhcp_supervisor = DHCPSupervisor(executable=config.dhcp.server.executable,
                                                 arguments=config.dhcp.server.arguments,
                                                 restart_interval=config.dhcp.server.restart_interval.total_seconds(),
                                                 terminate_timeout=config.dhcp.server.terminate_timeout.total_seconds())
            else:
                dhcp_supervisor = None
            netlink_monitor = NetlinkMonitor(command_queue)

            dhcp_manager = DHCPManager(dhcp_supervisor=dhcp_supervisor,
                                       netlink_monitor=netlink_monitor,
                                       config_filepath=self.vardata_path(config.dhcp.config_file) if config.dhcp.config_file is not None else None,
                                       hosts_filepath=self.vardata_path(config.dhcp.hosts_file) if config.dhcp.hosts_file is not None else None,
                                       file_group=config.dhcp.file_group,
                                       ip4_lease_time=int(config.dhcp.ip4_lease_time.total_seconds()),
                                       ip6_lease_time=int(config.dhcp.ip6_lease_time.total_seconds()))
            netlink_manager = NetlinkManager(netlink_monitor=netlink_monitor,
                                             table_name=config.netlink.table,
                                             default_svi_config=netlink_default_svi_config,
                                             svi_config=netlink_svi_config,
                                             ip4_all_nodes_address=config.general.ip4_all_nodes_address,
                                             ip6_all_nodes_address=config.general.ip6_all_nodes_address)
            lxd_manager = LXDManager(lxd_monitor=lxd_monitor,
                                     dhcp_manager=dhcp_manager,
                                     netlink_manager=netlink_manager,
                                     tags_enum=TagsBase('Tags', config.tag_items),  # type: ignore # FIXME: mypy doesn't realise this creates a new enum.
                                     default_svi_config=lxd_default_svi_config,
                                     svi_config=lxd_svi_config,
                                     enforce_eth_address=config.lxd.enforce_eth_address,
                                     enforce_ip6_ll_address=config.lxd.enforce_ip6_ll_address,
                                     id_attribute=config.lxd.id_attribute,
                                     ip4_all_nodes_address=config.general.ip4_all_nodes_address,
                                     ip6_all_nodes_address=config.general.ip6_all_nodes_address)

            lxd_monitor.start()
            exit_stack.callback(lxd_monitor.join)
            exit_stack.callback(lxd_monitor.stop)

            if dhcp_supervisor is not None:
                dhcp_supervisor.start()
                exit_stack.callback(dhcp_supervisor.join)
                exit_stack.callback(dhcp_supervisor.stop)

            netlink_monitor.start()
            exit_stack.callback(netlink_monitor.join)
            exit_stack.callback(netlink_monitor.stop)

            next_lxd_reload = time.monotonic()
            next_dhcp_reload = float('inf')
            next_dhcp_commit = float('inf')
            next_netlink_reload = float('inf')
            next_netlink_commit = float('inf')

            while True:
                now = time.monotonic()

                if now >= next_lxd_reload:
                    if not lxd_manager.initialised:
                        lxd_manager.reload()
                        if lxd_manager.initialised:
                            next_dhcp_reload = now
                            next_netlink_reload = now
                    else:
                        lxd_manager.reload()
                        next_dhcp_commit = now
                        next_netlink_commit = now
                    next_lxd_reload = now
                    next_lxd_reload += config.lxd.reload_interval.total_seconds() if lxd_manager.initialised else config.lxd.initial_reload_interval.total_seconds()
                    next_lxd_reload += config.lxd.reload_jitter.total_seconds() * (random.random() * 2 - 1)

                if now >= next_dhcp_reload:
                    dhcp_manager.reload()
                    next_dhcp_commit = now if dhcp_manager.dirty else float('inf')
                    next_dhcp_reload = now + config.dhcp.reload_interval.total_seconds()
                    next_dhcp_reload += config.dhcp.reload_jitter.total_seconds() * (random.random() * 2 - 1)

                if now >= next_dhcp_commit:
                    dhcp_manager.commit()
                    next_dhcp_commit = now + config.dhcp.retry_interval.total_seconds() if dhcp_manager.dirty else float('inf')

                if now >= next_netlink_reload:
                    netlink_manager.reload()
                    next_netlink_commit = now if netlink_manager.dirty else float('inf')
                    next_netlink_reload = now + config.netlink.reload_interval.total_seconds()
                    next_netlink_reload += config.netlink.reload_jitter.total_seconds() * (random.random() * 2 - 1)

                if now >= next_netlink_commit:
                    netlink_manager.commit()
                    next_netlink_commit = now + config.netlink.retry_interval.total_seconds() if netlink_manager.dirty else float('inf')

                timeout = min(next_lxd_reload - now,
                              next_dhcp_reload - now,
                              next_dhcp_commit - now,
                              next_netlink_reload - now,
                              next_netlink_commit - now)
                timeout = max(timeout, 0)

                try:
                    command = command_queue.get(timeout=timeout)
                except queue.Empty:
                    continue

                now = time.monotonic()

                if command is Commands.STOP:
                    break
                elif isinstance(command, (LXDEvent, NetlinkEvent)):
                    if lxd_manager.initialised:
                        command()
                        if dhcp_manager.dirty:
                            next_dhcp_commit = now
                        if netlink_manager.dirty:
                            next_netlink_commit = now
