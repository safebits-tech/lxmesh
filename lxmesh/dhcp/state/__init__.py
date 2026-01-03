__all__ = ['DHCPSVI',
           'DHCPEventContext', 'DHCPInitialiseContext', 'DHCPLoadContext', 'DHCPOperationContext']

import collections.abc
import dataclasses
import functools
import ipaddress
import logging
import socket
import types
import typing
import weakref

import pyroute2.netlink  # type: ignore[import-untyped]

from lxmesh.dhcp.exceptions import DHCPError
from lxmesh.dhcp.io import FileReplacement
from lxmesh.netlink.monitor import NetlinkMonitor
from lxmesh.state import EventContext, InitialiseContext, LoadContext, OperationContext


@dataclasses.dataclass
class DHCPSVI:
    refcount:   int
    name:       str
    index:      int | None = None
    mtu:        int | None = None
    networks:   list[ipaddress.IPv4Network | ipaddress.IPv6Network] | None = None


class DHCPBaseContext:
    def __init__(self, *,
                 svi_map: dict[str, DHCPSVI],
                 ip4_lease_time: int,
                 ip6_lease_time: int,
                 **kw: typing.Any):
        super().__init__(**kw)
        self.svi_map = svi_map
        self.ip4_lease_time = ip4_lease_time
        self.ip6_lease_time = ip6_lease_time


class DHCPEventContext(EventContext['DHCPEventContext', 'DHCPInitialiseContext', 'DHCPLoadContext', 'DHCPOperationContext'], DHCPBaseContext):
    pass


class DHCPInitialiseContext(InitialiseContext['DHCPEventContext', 'DHCPInitialiseContext', 'DHCPLoadContext', 'DHCPOperationContext']):
    def __init__(self, *,
                 netlink_monitor: NetlinkMonitor,
                 **kw: typing.Any):
        super().__init__(**kw)
        self.netlink_monitor = netlink_monitor

    def register_rt_subscription(self,
                                 handler: collections.abc.Callable[[DHCPEventContext, pyroute2.netlink.nlmsg], None],
                                 group: int,
                                 family: socket.AddressFamily,
                                 event: str,
                                 field_filters: dict[str, typing.Any] = {},
                                 attribute_filters: dict[str, typing.Any] = {}) -> None:
        if isinstance(handler, types.MethodType):
            handler_ref = weakref.WeakMethod(handler)
        else:
            handler_ref = weakref.ref(handler)
        handler = functools.partial(self.process_event, handler_ref, self.event_context_factory_ref)
        self.netlink_monitor.register_rt_subscription(handler, group, family, event, field_filters, attribute_filters)

    @staticmethod
    def process_event(handler_ref: weakref.ref[collections.abc.Callable[[DHCPEventContext, pyroute2.netlink.nlmsg], None]],
                      event_context_factory_ref: weakref.ref[collections.abc.Callable[[], DHCPEventContext]],
                      message: pyroute2.netlink.nlmsg) -> None:
        handler = handler_ref()
        if handler is None:
            logging.critical("Lost reference to event handler.")
            return
        event_context_factory = event_context_factory_ref()
        if event_context_factory is None:
            logging.critical("Lost reference to event context factory.")
            return
        event_context = event_context_factory()
        try:
            handler(event_context, message)
        except DHCPError as e:
            logging.error(e.message_sentence)
        except Exception:
            logging.exception("Unexpected exception while executing DHCP event handler:")


class DHCPLoadContext(LoadContext['DHCPEventContext', 'DHCPInitialiseContext', 'DHCPLoadContext', 'DHCPOperationContext'], DHCPBaseContext):
    def __init__(self, *, ipr: pyroute2.IPRoute, **kw: typing.Any):
        super().__init__(**kw)
        self.ipr = ipr


class DHCPOperationContext(OperationContext['DHCPEventContext', 'DHCPInitialiseContext', 'DHCPLoadContext', 'DHCPOperationContext'], DHCPBaseContext):
    def __init__(self, *,
                 ipr: pyroute2.IPRoute,
                 config_file: FileReplacement | None,
                 hosts_file: FileReplacement | None,
                 **kw: typing.Any):
        super().__init__(**kw)
        self.ipr = ipr
        self.config_file = config_file
        self.hosts_file = hosts_file
