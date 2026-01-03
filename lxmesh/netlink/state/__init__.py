__all__ = ['NFTable', 'NetlinkSVI', 'NetlinkSVIConfig',
           'NetlinkEventContext', 'NetlinkInitialiseContext', 'NetlinkLoadContext', 'NetlinkOperationContext']

import collections.abc
import dataclasses
import functools
import logging
import socket
import types
import typing
import weakref

import nftables as libnftables  # type: ignore[import-untyped]
import pyroute2  # type: ignore[import-untyped]
import pyroute2.netlink  # type: ignore[import-untyped]

from lxmesh.netlink.exceptions import NetlinkError
from lxmesh.netlink.monitor import NetlinkMonitor
from lxmesh.netlink.nftables import NFProto, NFTablesRaw
from lxmesh.state import EventContext, InitialiseContext, LoadContext, OperationContext


@dataclasses.dataclass
class NFTable:
    comment:    str | None  = None
    signature:  str | None  = None
    generation: int = 0


@dataclasses.dataclass
class NetlinkSVI:
    refcount:   int
    name:       str
    index:      int | None      = None
    table:      int | None      = None
    master:     int | None      = None
    vxlan:      dict[int, str]  = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class NetlinkSVIConfig:
    multicast:          bool
    host_routes_table:  int | None


class NetlinkBaseContext:
    def __init__(self, *,
                 instance_id: bytes,
                 nf_table_map: dict[tuple[str, str], NFTable],
                 svi_map: dict[str, NetlinkSVI],
                 table_name: str,
                 svi_config: dict[str, NetlinkSVIConfig],
                 default_svi_config: NetlinkSVIConfig,
                 **kw: typing.Any):
        super().__init__(**kw)
        self.instance_id = instance_id
        self.nf_table_map = nf_table_map
        self.svi_map = svi_map
        self.table_name = table_name
        self.svi_config = svi_config
        self.default_svi_config = default_svi_config


class NetlinkEventContext(EventContext['NetlinkEventContext', 'NetlinkInitialiseContext', 'NetlinkLoadContext', 'NetlinkOperationContext'], NetlinkBaseContext):
    pass


class NetlinkInitialiseContext(InitialiseContext['NetlinkEventContext', 'NetlinkInitialiseContext', 'NetlinkLoadContext', 'NetlinkOperationContext']):
    def __init__(self, *,
                 netlink_monitor: NetlinkMonitor,
                 table_name: str,
                 **kw: typing.Any):
        super().__init__(**kw)
        self.netlink_monitor = netlink_monitor
        self.table_name = table_name

    def register_nf_subscription(self,
                                 handler: collections.abc.Callable[[NetlinkEventContext, pyroute2.netlink.nlmsg], None],
                                 group: int,
                                 family: NFProto,
                                 operation: int,
                                 field_filters: dict[str, typing.Any] = {},
                                 attribute_filters: dict[str, typing.Any] = {}) -> None:
        if isinstance(handler, types.MethodType):
            handler_ref = weakref.WeakMethod(handler)
        else:
            handler_ref = weakref.ref(handler)
        handler = functools.partial(self.process_event, handler_ref, self.event_context_factory_ref)
        self.netlink_monitor.register_nf_subscription(handler, group, family, operation, field_filters, attribute_filters)

    def register_rt_subscription(self,
                                 handler: collections.abc.Callable[[NetlinkEventContext, pyroute2.netlink.nlmsg], None],
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
    def process_event(handler_ref: weakref.ref[collections.abc.Callable[[NetlinkEventContext, pyroute2.netlink.nlmsg], None]],
                      event_context_factory_ref: weakref.ref[collections.abc.Callable[[], NetlinkEventContext]],
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
        except NetlinkError as e:
            logging.error(e.message_sentence)
        except Exception:
            logging.exception("Unexpected exception while executing netlink event handler:")


class NetlinkLoadContext(LoadContext['NetlinkEventContext', 'NetlinkInitialiseContext', 'NetlinkLoadContext', 'NetlinkOperationContext'], NetlinkBaseContext):
    def __init__(self, *,
                 ipr: pyroute2.IPRoute,
                 nft: libnftables.Nftables,
                 nft_raw: NFTablesRaw,
                 **kw: typing.Any):
        super().__init__(**kw)
        self.ipr = ipr
        self.nft = nft
        self.nft_raw = nft_raw


class NetlinkOperationContext(OperationContext['NetlinkEventContext', 'NetlinkInitialiseContext', 'NetlinkLoadContext', 'NetlinkOperationContext'], NetlinkBaseContext):
    def __init__(self, *,
                 ipr: pyroute2.IPRoute,
                 nft: libnftables.Nftables,
                 nft_raw: NFTablesRaw,
                 **kw: typing.Any):
        super().__init__(**kw)
        self.ipr = ipr
        self.nft = nft
        self.nft_raw = nft_raw
