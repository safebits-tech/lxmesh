__all__ = ['NetlinkEvent', 'NetlinkMonitor']

import collections.abc
import dataclasses
import logging
import math
import os
import queue
import select
import socket
import threading
import typing

import pyroute2  # type: ignore # No stubs.
import pyroute2.netlink  # type: ignore # No stubs.

from lxmesh.netlink.iproute import IPRSocketExtended
from lxmesh.netlink.nftables import NFProto


@dataclasses.dataclass
class NetlinkEvent:
    message:    pyroute2.netlink.nlmsg
    handlers:   list[collections.abc.Callable[..., typing.Any]]

    def __call__(self) -> None:
        for handler in self.handlers:
            try:
                handler(self.message)
            except Exception:
                logging.exception("Unhandled exception in Netlink event handler '{}'".format(handler))


class NetlinkMonitor(threading.Thread):
    def __init__(self, command_queue: queue.SimpleQueue[typing.Any]) -> None:
        super().__init__(name="netlink-monitor")

        self.stopped = False
        self.command_queue = command_queue
        self.rd_pipe, self.wr_pipe = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)

        self.poll = select.poll()
        self.nf_sock: pyroute2.NFTSocket | None = None
        self.rt_sock: pyroute2.IPRSocket | None = None

        self.nf_groups = 0
        self.rt_groups = 0
        self.nf_filters: dict[tuple[NFProto, int], tuple[set[str], set[str]]] = {}
        self.rt_filters: dict[tuple[socket.AddressFamily, str], tuple[set[str], set[str]]] = {}
        self.nf_subscriptions: dict[tuple[NFProto, int, tuple[tuple[str, typing.Any], ...], tuple[tuple[str, typing.Any], ...]], list[collections.abc.Callable[[pyroute2.netlink.nlmsg], None]]] = {}
        self.rt_subscriptions: dict[tuple[socket.AddressFamily, str, tuple[tuple[str, typing.Any], ...], tuple[tuple[str, typing.Any], ...]], list[collections.abc.Callable[[pyroute2.netlink.nlmsg], None]]] = {}

    def register_nf_subscription(self,
                                 handler: collections.abc.Callable[[pyroute2.netlink.nlmsg], None],
                                 group: int,
                                 family: NFProto,
                                 operation: int,
                                 field_filters: dict[str, typing.Any] = {},
                                 attribute_filters: dict[str, typing.Any] = {}) -> None:
        if self.is_alive() or self.stopped:
            raise ValueError("cannot register subscription after monitoring thread is started")
        self.nf_groups |= 1 << (group - 1)
        try:
            if self.nf_filters[family, operation] != (set(field_filters.keys()), set(attribute_filters.keys())):
                raise ValueError("different set of attributes already registered for NF netlink family {} and operation {}".format(family, operation))
        except KeyError:
            self.nf_filters[family, operation] = (set(field_filters.keys()), set(attribute_filters.keys()))
        fields = list(field_filters.items())
        fields.sort()
        attributes = list(attribute_filters.items())
        attributes.sort()
        self.nf_subscriptions.setdefault((family, operation, tuple(fields), tuple(attributes)), []).append(handler)

    def register_rt_subscription(self,
                                 handler: collections.abc.Callable[[pyroute2.netlink.nlmsg], None],
                                 group: int,
                                 family: socket.AddressFamily,
                                 event: str,
                                 field_filters: dict[str, typing.Any] = {},
                                 attribute_filters: dict[str, typing.Any] = {}) -> None:
        if self.is_alive() or self.stopped:
            raise ValueError("cannot register subscription after monitoring thread is started")
        self.rt_groups |= 1 << (group - 1)
        try:
            if self.rt_filters[family, event] != (set(field_filters.keys()), set(attribute_filters.keys())):
                raise ValueError("different set of attributes already registered for RT netlink family {} and event {}".format(family, event))
        except KeyError:
            self.rt_filters[family, event] = (set(field_filters.keys()), set(attribute_filters.keys()))
        fields = list(field_filters.items())
        fields.sort()
        attributes = list(attribute_filters.items())
        attributes.sort()
        self.rt_subscriptions.setdefault((family, event, tuple(fields), tuple(attributes)), []).append(handler)

    def start(self) -> None:
        if self.is_alive() or self.stopped:
            raise ValueError("cannot restart monitoring thread")
        self._init_nf_sock()
        self._init_rt_sock()
        super().start()

    def stop(self) -> None:
        if not self.stopped:
            self.stopped = True
            try:
                os.write(self.wr_pipe, b'\x00')
            except BlockingIOError:
                pass

    def join(self, *args: typing.Any, **kw: typing.Any) -> None:
        if not self.stopped:
            raise ValueError("monitoring thread must be stopped before joining")
        super().join(*args, **kw)
        if self.nf_sock is not None:
            self.nf_sock.close()
            self.nf_sock = None
        if self.rt_sock is not None:
            self.rt_sock.close()
            self.rt_sock = None

    def _init_nf_sock(self) -> None:
        self.nf_sock = pyroute2.NFTSocket()
        try:
            self.nf_sock.bind(groups=self.nf_groups)
        except Exception as e:
            logging.error("Failed to bind netlink NF socket: {}.".format(e))
            self.nf_sock.close()
            self.nf_sock = None
        else:
            self.nf_sock.setblocking(False)
            self.poll.register(self.nf_sock, select.POLLIN | select.POLLERR)

    def _init_rt_sock(self) -> None:
        self.rt_sock = IPRSocketExtended()
        try:
            self.rt_sock.bind(groups=self.rt_groups)
        except Exception as e:
            logging.error("Failed to bind netlink RT socket: {}.".format(e))
            self.rt_sock.close()
            self.rt_sock = None
        else:
            self.rt_sock.setblocking(False)
            self.poll.register(self.rt_sock, select.POLLIN | select.POLLERR)

    def run(self) -> None:
        self.poll.register(self.rd_pipe, select.POLLIN)
        while not self.stopped:
            timeout = float('inf')

            if self.nf_sock is None:
                self._init_nf_sock()
            if self.rt_sock is None:
                self._init_rt_sock()
            if self.nf_sock is None:
                timeout = min(timeout, 1.0)
            if self.rt_sock is None:
                timeout = min(timeout, 1.0)

            poll_result = self.poll.poll(max(timeout, 0) * 1000 if not math.isinf(timeout) else None)
            for fd, fd_events in poll_result:
                if self.nf_sock is not None and fd == self.nf_sock.fileno():
                    if fd_events & select.EPOLLERR:
                        self.nf_sock.close()
                        self.nf_sock = None
                        continue
                    try:
                        results = self.nf_sock.get()
                    except BlockingIOError:
                        continue
                    if not results:
                        self.nf_sock.close()
                        self.nf_sock = None
                        continue
                    for msg in results:
                        try:
                            self.process_nf_message(msg)
                        except Exception:
                            logging.exception("Unexpected exception while processing netlink event message:")
                elif self.rt_sock is not None and fd == self.rt_sock.fileno():
                    if fd_events & select.EPOLLERR:
                        self.rt_sock.close()
                        self.rt_sock = None
                        continue
                    try:
                        results = self.rt_sock.get()
                    except BlockingIOError:
                        continue
                    if not results:
                        self.rt_sock.close()
                        self.rt_sock = None
                        continue
                    for msg in results:
                        try:
                            self.process_rt_message(msg)
                        except Exception:
                            logging.exception("Unexpected exception while processing netlink event message:")
                elif fd == self.rd_pipe:
                    try:
                        os.read(self.rd_pipe, 4096)
                    except BlockingIOError:
                        pass

    def process_nf_message(self, msg: pyroute2.netlink.nlmsg) -> None:
        try:
            family = NFProto(msg['nfgen_family'])
        except (KeyError, ValueError):
            family = NFProto.UNSPEC
        operation: int = msg['header']['type']
        try:
            field_names, attribute_names = self.nf_filters[family, operation]
        except KeyError:
            return
        try:
            field_values = list(map(msg.__getitem__, field_names))
        except Exception as e:
            logging.warning("Failed to get fields from NF netlink message: {}.".format(e))
            return
        else:
            fields = list(zip(field_names, field_values))
            fields.sort()
        try:
            attribute_values = list(map(msg.get_attr, attribute_names))
        except Exception as e:
            logging.warning("Failed to get attributes from NF netlink message: {}.".format(e))
            return
        else:
            attributes = list(zip(attribute_names, attribute_values))
            attributes.sort()
        try:
            handlers = self.nf_subscriptions[family, operation, tuple(fields), tuple(attributes)]
        except KeyError:
            return
        else:
            self.command_queue.put(NetlinkEvent(message=msg, handlers=handlers))

    def process_rt_message(self, msg: pyroute2.netlink.nlmsg) -> None:
        try:
            family = socket.AddressFamily(msg['family'])
        except (KeyError, ValueError):
            family = socket.AF_UNSPEC
        event: str = msg['event']
        try:
            field_names, attribute_names = self.rt_filters[family, event]
        except KeyError:
            return
        try:
            field_values = list(map(msg.__getitem__, field_names))
        except Exception as e:
            logging.warning("Failed to get fields from NF netlink message: {}.".format(e))
            return
        else:
            fields = list(zip(field_names, field_values))
            fields.sort()
        try:
            attribute_values = list(map(msg.get_attr, attribute_names))
        except Exception as e:
            logging.warning("Failed to get attributes from RT netlink message: {}.".format(e))
            return
        else:
            attributes = list(zip(attribute_names, attribute_values))
            attributes.sort()
        try:
            handlers = self.rt_subscriptions[family, event, tuple(fields), tuple(attributes)]
        except KeyError:
            return
        self.command_queue.put(NetlinkEvent(message=msg, handlers=handlers))
