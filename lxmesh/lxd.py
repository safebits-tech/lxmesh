from __future__ import annotations

__all__ = ['LXDEvent', 'LXDManager', 'LXDMonitor', 'LXDSVIConfig', 'TagsBase']

import collections.abc
import contextlib
import dataclasses
import enum
import functools
import ipaddress
import json
import logging
import math
import operator
import os
import queue
import select
import socket
import threading
import time
import typing
import types
import uuid
import weakref

import pylxd  # type: ignore[import-untyped]
import pylxd.models.container  # type: ignore[import-untyped]
import websockets.exceptions

from lxmesh.dhcp import DHCPManager, DHCPState
from lxmesh.exceptions import ApplicationError
from lxmesh.netlink import NetlinkManager, NetlinkState
from lxmesh.websockets import NonblockingWSClient


TTags = typing.TypeVar('TTags', bound='TagsBase')


class LXDError(ApplicationError):
    pass


def ethernet2ipv6eui64(network: ipaddress.IPv6Network, eth_address: str, /) -> ipaddress.IPv6Address:
    if network.prefixlen > 64:
        raise ValueError("cannot construct EUI-64 IPv6 address using a network smaller than /64")
    try:
        eui_64 = bytes.fromhex(eth_address.replace(':', ''))
        if len(eui_64) != 6:
            raise ValueError
    except ValueError:
        raise ValueError("invalid ethernet address: {}".format(eth_address)) from None
    eui_64 = eui_64[:3] + b'\xff\xfe' + eui_64[3:]
    return network.network_address + (int.from_bytes(eui_64, byteorder='big') ^ (1 << 57))


@dataclasses.dataclass
class LXDEvent:
    message:    dict[str, typing.Any]
    handlers:   list[collections.abc.Callable[[dict[str, typing.Any]], None]]

    def __call__(self) -> None:
        for handler in self.handlers:
            try:
                handler(self.message)
            except Exception:
                logging.exception("Unhandled exception in LXD event handler '{}'".format(handler))


@enum.unique
class TagsBase(enum.IntFlag):
    def __str__(self) -> str:
        return self.name or 'unknown'


class Service(typing.NamedTuple):
    protocol:   typing.Literal['sctp', 'tcp', 'udp']
    port:       int

    @classmethod
    def parse(cls, description: str) -> Service:
        try:
            protocol, port_str = description.split('/', 1)
        except ValueError:
            raise ValueError("expected 'protocol/port'") from None
        if protocol not in ('sctp', 'tcp', 'udp'):
            raise ValueError("unknown protocol '{}'".format(protocol)) from None
        protocol = typing.cast(typing.Literal['sctp', 'tcp', 'udp'], protocol)  # FIXME: this shouldn't be needed by mypy.
        try:
            port = int(port_str, 10)
            if not (0 < port < 2**16):
                raise ValueError("port number '{}' out of range".format(port))
        except ValueError:
            raise ValueError("invalid port number '{}'".format(port))

        return cls(protocol=protocol, port=port)

    def __str__(self) -> str:
        return "{}/{}".format(self.protocol, self.port)


@dataclasses.dataclass
class LXDSVIConfig:
    mark:           int
    host_routes:    bool


class LXDNetworkDevice:
    def __init__(self, *,
                 vpc: str,
                 dhcp_manager: DHCPManager,
                 netlink_manager: NetlinkManager,
                 tags_enum: type[TagsBase],
                 default_svi_config: LXDSVIConfig,
                 svi_config: dict[str, LXDSVIConfig] = {},
                 ip4_all_nodes_address: ipaddress.IPv4Address | None = None,
                 ip6_all_nodes_address: ipaddress.IPv6Address | None = None) -> None:
        self.vpc = vpc
        self.netlink_manager = netlink_manager
        self.dhcp_manager = dhcp_manager
        self.tags_enum = tags_enum
        self.default_svi_config = default_svi_config
        self.svi_config = svi_config
        self.ip4_all_nodes_address = ip4_all_nodes_address
        self.ip6_all_nodes_address = ip6_all_nodes_address

    @contextlib.contextmanager
    def attributes_transaction(self) -> collections.abc.Iterator[None]:
        attributes = self.__dict__.copy()
        try:
            yield None
        except BaseException:
            self.__dict__ = attributes
            raise

    def reset(self) -> None:
        self.device_name = None
        self.device_address = None
        self.tags = frozenset()
        self.ip4_address = None
        self.ip6_address = None
        self.ip6_link_address = None
        self.in_services = frozenset()
        self.out_services = frozenset()
        self.svi = None
        self.instance_name = None

    @property
    def instance_name(self) -> str | None:
        return typing.cast(str | None, self.__dict__.get('instance_name', None))

    @instance_name.setter
    def instance_name(self, value: str | None) -> None:
        old_value: str | None = self.__dict__.get('instance_name', None)
        if old_value == value:
            return
        if old_value is not None and value is not None:
            logging.debug("LXD instance '{}' has new name '{}'.".format(old_value, value))

        with self.dhcp_manager:
            if self.device_address is not None and self.svi is not None and (self.ip4_address is not None or self.ip6_address is not None):
                self.dhcp_manager.remove(DHCPState.Host(svi=self.svi, name=old_value, device_address=self.device_address,
                                                        ip4_address=self.ip4_address, ip6_address=self.ip6_address))
                self.dhcp_manager.add(DHCPState.Host(svi=self.svi, name=value, device_address=self.device_address,
                                                     ip4_address=self.ip4_address, ip6_address=self.ip6_address))

        self.__dict__['instance_name'] = value

    @property
    def svi(self) -> str | None:
        return typing.cast(str | None, self.__dict__.get('svi', None))

    @svi.setter
    def svi(self, value: str | None) -> None:
        old_value: str | None = self.__dict__.get('svi', None)
        if old_value == value:
            return
        if value is not None and old_value is not None:
            logging.info("LXD instance '{}' has new SVI '{}' for VPC '{}' (previously '{}').".format(self.instance_name, value, self.vpc, old_value))
        elif value is not None:
            logging.info("LXD instance '{}' has VPC '{}' connected to SVI '{}'.".format(self.instance_name, self.vpc, value))
        else:
            logging.info("LXD instance '{}' no longer has VPC '{}' connected to an SVI (previously '{}').".format(self.instance_name, self.vpc, old_value))

        with self.dhcp_manager, self.netlink_manager, contextlib.ExitStack() as exit_stack:
            if old_value is not None:
                old_svi_config = self.svi_config.get(old_value, self.default_svi_config)
                if self.device_name is not None:
                    self.netlink_manager.remove(NetlinkState.Device(name=self.device_name, svi=old_value))
                    self.netlink_manager.remove(NetlinkState.Mark(device=self.device_name, mark=old_svi_config.mark | self.tags_mark))
                    if self.ip4_all_nodes_address is not None:
                        self.netlink_manager.remove(NetlinkState.MDBEntry(svi=old_value, device=self.device_name, group=self.ip4_all_nodes_address))
                    if self.ip6_all_nodes_address is not None:
                        self.netlink_manager.remove(NetlinkState.MDBEntry(svi=old_value, device=self.device_name, group=self.ip6_all_nodes_address))
                if self.device_address is not None:
                    for address in [self.ip4_address, self.ip6_address]:
                        if address is None or not old_svi_config.host_routes:
                            continue
                        self.netlink_manager.remove(NetlinkState.Route(svi=old_value, prefix=ipaddress.ip_network(address)))
                    for address in [self.ip4_address, self.ip6_address, self.ip6_link_address]:
                        if address is None:
                            continue
                        self.netlink_manager.remove(NetlinkState.Neighbour(svi=old_value, address=address, lladdr=self.device_address))
                    if self.ip4_address is not None or self.ip6_address is not None:
                        self.dhcp_manager.remove(DHCPState.Host(svi=old_value, name=self.instance_name, device_address=self.device_address,
                                                                ip4_address=self.ip4_address, ip6_address=self.ip6_address))

                self.dhcp_manager.unregister_svi(old_value)

                @exit_stack.push
                def dhcp_register_old_svi(exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: types.TracebackType | None) -> bool:
                    if exc_type is not None:
                        self.dhcp_manager.register_svi(old_value)
                    return False

                self.netlink_manager.unregister_svi(old_value)

                @exit_stack.push
                def netlink_register_old_svi(exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: types.TracebackType | None) -> bool:
                    if exc_type is not None:
                        self.netlink_manager.register_svi(old_value)
                    return False

            if value is not None:
                self.dhcp_manager.register_svi(value)

                @exit_stack.push
                def dhcp_unregister_new_svi(exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: types.TracebackType | None) -> bool:
                    if exc_type is not None:
                        self.dhcp_manager.unregister_svi(value)
                    return False

                self.netlink_manager.register_svi(value)

                @exit_stack.push
                def netlink_unregister_new_svi(exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: types.TracebackType | None) -> bool:
                    if exc_type is not None:
                        self.netlink_manager.unregister_svi(value)
                    return False

                svi_config = self.svi_config.get(value, self.default_svi_config)
                if self.device_name is not None:
                    self.netlink_manager.add(NetlinkState.Device(name=self.device_name, svi=value))
                    self.netlink_manager.add(NetlinkState.Mark(device=self.device_name, mark=svi_config.mark | self.tags_mark))
                    if self.ip4_all_nodes_address is not None:
                        self.netlink_manager.add(NetlinkState.MDBEntry(svi=value, device=self.device_name, group=self.ip4_all_nodes_address))
                    if self.ip6_all_nodes_address is not None:
                        self.netlink_manager.add(NetlinkState.MDBEntry(svi=value, device=self.device_name, group=self.ip6_all_nodes_address))
                if self.device_address is not None:
                    for address in [self.ip4_address, self.ip6_address]:
                        if address is None or not svi_config.host_routes:
                            continue
                        self.netlink_manager.add(NetlinkState.Route(svi=value, prefix=ipaddress.ip_network(address)))
                    for address in [self.ip4_address, self.ip6_address, self.ip6_link_address]:
                        if address is None:
                            continue
                        self.netlink_manager.add(NetlinkState.Neighbour(svi=value, address=address, lladdr=self.device_address))
                    if self.ip4_address is not None or self.ip6_address is not None:
                        self.dhcp_manager.add(DHCPState.Host(svi=value, name=self.instance_name, device_address=self.device_address,
                                                             ip4_address=self.ip4_address, ip6_address=self.ip6_address))

        self.__dict__['svi'] = value

    @property
    def device_name(self) -> str | None:
        return typing.cast(str | None, self.__dict__.get('device_name', None))

    @device_name.setter
    def device_name(self, value: str | None) -> None:
        old_value: str | None = self.__dict__.get('device_name', None)
        if old_value == value:
            return
        if value is not None and old_value is not None:
            logging.info("LXD instance '{}' has new host device name '{}' for VPC '{}' (previously '{}').".format(self.instance_name, value, self.vpc, old_value))
        elif value is not None:
            logging.info("LXD instance '{}' has VPC '{}' linked to host device name '{}'.".format(self.instance_name, self.vpc, value))
        else:
            logging.info("LXD instance '{}' no longer has VPC '{}' linked to a host device (previously '{}').".format(self.instance_name, self.vpc, old_value))

        with self.netlink_manager:
            if old_value is not None:
                if self.svi is not None:
                    svi_config = self.svi_config.get(self.svi, self.default_svi_config)
                    self.netlink_manager.remove(NetlinkState.Device(name=old_value, svi=self.svi))
                    self.netlink_manager.remove(NetlinkState.Mark(device=old_value, mark=svi_config.mark | self.tags_mark))
                    if self.ip4_all_nodes_address is not None:
                        self.netlink_manager.remove(NetlinkState.MDBEntry(svi=self.svi, device=old_value, group=self.ip4_all_nodes_address))
                    if self.ip6_all_nodes_address is not None:
                        self.netlink_manager.remove(NetlinkState.MDBEntry(svi=self.svi, device=old_value, group=self.ip6_all_nodes_address))
                if self.device_address is not None:
                    self.netlink_manager.remove(NetlinkState.FDBEntry(lladdr=self.device_address, device=old_value))
                for protocol, port in self.in_services:
                    self.netlink_manager.remove(NetlinkState.Service(direction='in', device=old_value, protocol=protocol, port=port))
                for protocol, port in self.out_services:
                    self.netlink_manager.remove(NetlinkState.Service(direction='out', device=old_value, protocol=protocol, port=port))
                for family, address in [(socket.AF_BRIDGE,  self.device_address),
                                        (socket.AF_INET,    self.ip4_address),
                                        (socket.AF_INET6,   self.ip6_address),
                                        (socket.AF_INET6,   self.ip6_link_address)]:
                    if address is None:
                        continue
                    self.netlink_manager.remove(NetlinkState.ValidatedAddress(device=old_value, family=family, address=address))

            if value is not None:
                if self.svi is not None:
                    svi_config = self.svi_config.get(self.svi, self.default_svi_config)
                    self.netlink_manager.add(NetlinkState.Device(name=value, svi=self.svi))
                    self.netlink_manager.add(NetlinkState.Mark(device=value, mark=svi_config.mark | self.tags_mark))
                    if self.ip4_all_nodes_address is not None:
                        self.netlink_manager.add(NetlinkState.MDBEntry(svi=self.svi, device=value, group=self.ip4_all_nodes_address))
                    if self.ip6_all_nodes_address is not None:
                        self.netlink_manager.add(NetlinkState.MDBEntry(svi=self.svi, device=value, group=self.ip6_all_nodes_address))
                if self.device_address is not None:
                    self.netlink_manager.add(NetlinkState.FDBEntry(lladdr=self.device_address, device=value))
                for protocol, port in self.in_services:
                    self.netlink_manager.add(NetlinkState.Service(direction='in', device=value, protocol=protocol, port=port))
                for protocol, port in self.out_services:
                    self.netlink_manager.add(NetlinkState.Service(direction='out', device=value, protocol=protocol, port=port))
                for family, address in [(socket.AF_BRIDGE,  self.device_address),
                                        (socket.AF_INET,    self.ip4_address),
                                        (socket.AF_INET6,   self.ip6_address),
                                        (socket.AF_INET6,   self.ip6_link_address)]:
                    if address is None:
                        continue
                    self.netlink_manager.add(NetlinkState.ValidatedAddress(device=value, family=family, address=address))

        self.__dict__['device_name'] = value

    @property
    def device_address(self) -> str | None:
        return typing.cast(str | None, self.__dict__.get('device_address', None))

    @device_address.setter
    def device_address(self, value: str | None) -> None:
        old_value: str | None = self.__dict__.get('device_address', None)
        if old_value == value:
            return
        if value is not None and old_value is not None:
            logging.info("LXD instance '{}' has new device address '{}' for VPC '{}' (previously '{}').".format(self.instance_name, value, self.vpc, old_value))
        elif value is not None:
            logging.info("LXD instance '{}' has device address '{}' for VPC '{}'.".format(self.instance_name, value, self.vpc))
        else:
            logging.info("LXD instance '{}' no longer has a device address for VPC '{}' (previously '{}').".format(self.instance_name, self.vpc, old_value))

        with self.dhcp_manager, self.netlink_manager:
            if old_value is not None:
                if self.device_name is not None:
                    self.netlink_manager.remove(NetlinkState.FDBEntry(lladdr=old_value, device=self.device_name))
                    self.netlink_manager.remove(NetlinkState.ValidatedAddress(device=self.device_name, family=socket.AF_BRIDGE, address=old_value))
                if self.svi is not None:
                    svi_config = self.svi_config.get(self.svi, self.default_svi_config)
                    for address in [self.ip4_address, self.ip6_address]:
                        if address is None or not svi_config.host_routes:
                            continue
                        self.netlink_manager.remove(NetlinkState.Route(svi=self.svi, prefix=ipaddress.ip_network(address)))
                    for address in [self.ip4_address, self.ip6_address, self.ip6_link_address]:
                        if address is None:
                            continue
                        self.netlink_manager.remove(NetlinkState.Neighbour(svi=self.svi, address=address, lladdr=old_value))
                    if self.ip4_address is not None or self.ip6_address is not None:
                        self.dhcp_manager.remove(DHCPState.Host(svi=self.svi, name=self.instance_name, device_address=old_value,
                                                                ip4_address=self.ip4_address, ip6_address=self.ip6_address))

            if value is not None:
                if self.device_name is not None:
                    self.netlink_manager.add(NetlinkState.FDBEntry(lladdr=value, device=self.device_name))
                    self.netlink_manager.add(NetlinkState.ValidatedAddress(device=self.device_name, family=socket.AF_BRIDGE, address=value))
                if self.svi is not None:
                    svi_config = self.svi_config.get(self.svi, self.default_svi_config)
                    for address in [self.ip4_address, self.ip6_address]:
                        if address is None or not svi_config.host_routes:
                            continue
                        self.netlink_manager.add(NetlinkState.Route(svi=self.svi, prefix=ipaddress.ip_network(address)))
                    for address in [self.ip4_address, self.ip6_address, self.ip6_link_address]:
                        if address is None:
                            continue
                        self.netlink_manager.add(NetlinkState.Neighbour(svi=self.svi, address=address, lladdr=value))
                    if self.ip4_address is not None or self.ip6_address is not None:
                        self.dhcp_manager.add(DHCPState.Host(svi=self.svi, name=self.instance_name, device_address=value,
                                                             ip4_address=self.ip4_address, ip6_address=self.ip6_address))

        self.__dict__['device_address'] = value

    @property
    def tags(self) -> frozenset[TagsBase]:
        return typing.cast(frozenset[TagsBase], self.__dict__.get('tags', frozenset()))

    @tags.setter
    def tags(self, value: collections.abc.Iterable[TagsBase]) -> None:
        old_value: frozenset[TagsBase] = self.__dict__.get('tags', frozenset())
        value = frozenset(value)
        if old_value == value:
            return
        if value and old_value:
            logging.info("LXD instance '{}' has new tags '{}' for VPC '{}' (previously '{}').".format(self.instance_name, ", ".join(map(str, value)), self.vpc, ", ".join(map(str, old_value))))
        elif value:
            logging.info("LXD instance '{}' has tags '{}' for VPC '{}'.".format(self.instance_name, ", ".join(map(str, value)), self.vpc))
        else:
            logging.info("LXD instance '{}' no longer has tags for VPC '{}' (previously '{}').".format(self.instance_name, self.vpc, ", ".join(map(str, old_value))))

        with self.netlink_manager:
            if self.svi is not None and self.device_name is not None:
                svi_config = self.svi_config.get(self.svi, self.default_svi_config)
                self.netlink_manager.remove(NetlinkState.Mark(device=self.device_name, mark=svi_config.mark | self.tags_mark))
                self.netlink_manager.add(NetlinkState.Mark(device=self.device_name, mark=svi_config.mark | self.compute_tags_mark(value)))

        self.__dict__['tags'] = value

    def compute_tags_mark(self, tags: collections.abc.Iterable[TagsBase]) -> int:
        return int(functools.reduce(operator.or_, tags, self.tags_enum(0)))

    @property
    def tags_mark(self) -> int:
        return self.compute_tags_mark(self.tags)

    @property
    def ip4_address(self) -> ipaddress.IPv4Address | None:
        return typing.cast(ipaddress.IPv4Address | None, self.__dict__.get('ip4_address', None))

    @ip4_address.setter
    def ip4_address(self, value: ipaddress.IPv4Address | None) -> None:
        old_value: ipaddress.IPv4Address | None = self.__dict__.get('ip4_address', None)
        if old_value == value:
            return
        if value is not None and old_value is not None:
            logging.info("LXD instance '{}' has new IPv4 address '{}' for VPC '{}' (previously '{}').".format(self.instance_name, value, self.vpc, old_value))
        elif value is not None:
            logging.info("LXD instance '{}' has IPv4 address '{}' for VPC '{}'.".format(self.instance_name, value, self.vpc))
        else:
            logging.info("LXD instance '{}' no longer has an IPv4 address for VPC '{}' (previously '{}').".format(self.instance_name, self.vpc, old_value))

        with self.dhcp_manager, self.netlink_manager:
            if old_value is not None:
                if self.device_name is not None:
                    self.netlink_manager.remove(NetlinkState.ValidatedAddress(device=self.device_name, family=socket.AF_INET, address=old_value))
                if self.device_address is not None and self.svi is not None:
                    self.netlink_manager.remove(NetlinkState.Neighbour(svi=self.svi, address=old_value, lladdr=self.device_address))
                    svi_config = self.svi_config.get(self.svi, self.default_svi_config)
                    if svi_config.host_routes:
                        self.netlink_manager.remove(NetlinkState.Route(svi=self.svi, prefix=ipaddress.ip_network(old_value)))
            if self.device_address is not None and self.svi is not None and (old_value is not None or self.ip6_address is not None):
                self.dhcp_manager.remove(DHCPState.Host(svi=self.svi, name=self.instance_name, device_address=self.device_address,
                                                        ip4_address=old_value, ip6_address=self.ip6_address))

            if value is not None:
                if self.device_name is not None:
                    self.netlink_manager.add(NetlinkState.ValidatedAddress(device=self.device_name, family=socket.AF_INET, address=value))
                if self.device_address is not None and self.svi is not None:
                    self.netlink_manager.add(NetlinkState.Neighbour(svi=self.svi, address=value, lladdr=self.device_address))
                    svi_config = self.svi_config.get(self.svi, self.default_svi_config)
                    if svi_config.host_routes:
                        self.netlink_manager.add(NetlinkState.Route(svi=self.svi, prefix=ipaddress.ip_network(value)))
            if self.device_address is not None and self.svi is not None and (value is not None or self.ip6_address is not None):
                self.dhcp_manager.add(DHCPState.Host(svi=self.svi, name=self.instance_name, device_address=self.device_address,
                                                     ip4_address=value, ip6_address=self.ip6_address))

        self.__dict__['ip4_address'] = value

    @property
    def ip6_address(self) -> ipaddress.IPv6Address | None:
        return typing.cast(ipaddress.IPv6Address | None, self.__dict__.get('ip6_address', None))

    @ip6_address.setter
    def ip6_address(self, value: ipaddress.IPv6Address | None) -> None:
        old_value: ipaddress.IPv6Address | None = self.__dict__.get('ip6_address', None)
        if old_value == value:
            return
        if value is not None and old_value is not None:
            logging.info("LXD instance '{}' has new IPv6 address '{}' for VPC '{}' (previously '{}').".format(self.instance_name, value, self.vpc, old_value))
        elif value is not None:
            logging.info("LXD instance '{}' has IPv6 address '{}' for VPC '{}'.".format(self.instance_name, value, self.vpc))
        else:
            logging.info("LXD instance '{}' no longer has an IPv6 address for VPC '{}' (previously '{}').".format(self.instance_name, self.vpc, old_value))

        with self.dhcp_manager, self.netlink_manager:
            if old_value is not None:
                if self.device_name is not None:
                    self.netlink_manager.remove(NetlinkState.ValidatedAddress(device=self.device_name, family=socket.AF_INET6, address=old_value))
                if self.device_address is not None and self.svi is not None:
                    self.netlink_manager.remove(NetlinkState.Neighbour(svi=self.svi, address=old_value, lladdr=self.device_address))
                    svi_config = self.svi_config.get(self.svi, self.default_svi_config)
                    if svi_config.host_routes:
                        self.netlink_manager.remove(NetlinkState.Route(svi=self.svi, prefix=ipaddress.ip_network(old_value)))
            if self.device_address is not None and self.svi is not None and (old_value is not None or self.ip4_address is not None):
                self.dhcp_manager.remove(DHCPState.Host(svi=self.svi, name=self.instance_name, device_address=self.device_address,
                                                        ip4_address=self.ip4_address, ip6_address=old_value))

            if value is not None:
                if self.device_name is not None:
                    self.netlink_manager.add(NetlinkState.ValidatedAddress(device=self.device_name, family=socket.AF_INET6, address=value))
                if self.device_address is not None and self.svi is not None:
                    self.netlink_manager.add(NetlinkState.Neighbour(svi=self.svi, address=value, lladdr=self.device_address))
                    svi_config = self.svi_config.get(self.svi, self.default_svi_config)
                    if svi_config.host_routes:
                        self.netlink_manager.add(NetlinkState.Route(svi=self.svi, prefix=ipaddress.ip_network(value)))
            if self.device_address is not None and self.svi is not None and (value is not None or self.ip4_address is not None):
                self.dhcp_manager.add(DHCPState.Host(svi=self.svi, name=self.instance_name, device_address=self.device_address,
                                                     ip4_address=self.ip4_address, ip6_address=value))

        self.__dict__['ip6_address'] = value

    @property
    def ip6_link_address(self) -> ipaddress.IPv6Address | None:
        return typing.cast(ipaddress.IPv6Address | None, self.__dict__.get('ip6_link_address', None))

    @ip6_link_address.setter
    def ip6_link_address(self, value: ipaddress.IPv6Address | None) -> None:
        old_value: ipaddress.IPv6Address | None = self.__dict__.get('ip6_link_address', None)
        if old_value == value:
            return
        if value is not None and old_value is not None:
            logging.info("LXD instance '{}' has new IPv6 link-local address '{}' for VPC '{}' (previously '{}').".format(self.instance_name, value, self.vpc, old_value))
        elif value is not None:
            logging.info("LXD instance '{}' has IPv6 link-local address '{}' for VPC '{}'.".format(self.instance_name, value, self.vpc))
        else:
            logging.info("LXD instance '{}' no longer has an IPv6 link-local address for VPC '{}' (previously '{}').".format(self.instance_name, self.vpc, old_value))

        with self.netlink_manager:
            if old_value is not None:
                if self.device_name is not None:
                    self.netlink_manager.remove(NetlinkState.ValidatedAddress(device=self.device_name, family=socket.AF_INET6, address=old_value))
                if self.device_address is not None and self.svi is not None:
                    self.netlink_manager.remove(NetlinkState.Neighbour(svi=self.svi, address=old_value, lladdr=self.device_address))

            if value is not None:
                if self.device_name is not None:
                    self.netlink_manager.add(NetlinkState.ValidatedAddress(device=self.device_name, family=socket.AF_INET6, address=value))
                if self.device_address is not None and self.svi is not None:
                    self.netlink_manager.add(NetlinkState.Neighbour(svi=self.svi, address=value, lladdr=self.device_address))

        self.__dict__['ip6_link_address'] = value

    @property
    def in_services(self) -> frozenset[Service]:
        return typing.cast(frozenset[Service], self.__dict__.get('in_services', frozenset()))

    @in_services.setter
    def in_services(self, value: collections.abc.Iterable[Service]) -> None:
        old_value = self.__dict__.get('in_services', frozenset())
        value = frozenset(value)

        with self.netlink_manager:
            if self.device_name is not None:
                for proto, port in old_value - value:
                    logging.info("LXD instance '{}' no longer has ingress service '{}/{}' for VPC '{}'.".format(self.instance_name, proto, port, self.vpc))
                    self.netlink_manager.remove(NetlinkState.Service(direction='in', device=self.device_name, protocol=proto, port=port))
                for proto, port in value - old_value:
                    logging.info("LXD instance '{}' has new ingress service '{}/{}' for VPC '{}'.".format(self.instance_name, proto, port, self.vpc))
                    self.netlink_manager.add(NetlinkState.Service(direction='in', device=self.device_name, protocol=proto, port=port))

        self.__dict__['in_services'] = value

    @property
    def out_services(self) -> frozenset[Service]:
        return typing.cast(frozenset[Service], self.__dict__.get('out_services', frozenset()))

    @out_services.setter
    def out_services(self, value: collections.abc.Iterable[Service]) -> None:
        old_value = self.__dict__.get('out_services', frozenset())
        value = frozenset(value)

        with self.netlink_manager:
            if self.device_name is not None:
                for proto, port in old_value - value:
                    logging.info("LXD instance '{}' no longer has egress service '{}/{}' for VPC '{}'.".format(self.instance_name, proto, port, self.vpc))
                    self.netlink_manager.remove(NetlinkState.Service(direction='out', device=self.device_name, protocol=proto, port=port))
                for proto, port in value - old_value:
                    logging.info("LXD instance '{}' has new egress service '{}/{}' for VPC '{}'.".format(self.instance_name, proto, port, self.vpc))
                    self.netlink_manager.add(NetlinkState.Service(direction='out', device=self.device_name, protocol=proto, port=port))

        self.__dict__['out_services'] = value


class LXDInstance:
    def __init__(self, *,
                 id: str,
                 name: str,
                 dhcp_manager: DHCPManager,
                 netlink_manager: NetlinkManager,
                 tags_enum: type[TagsBase],
                 default_svi_config: LXDSVIConfig,
                 svi_config: dict[str, LXDSVIConfig] = {},
                 enforce_eth_address: bool,
                 enforce_ip6_ll_address: bool,
                 ip4_all_nodes_address: ipaddress.IPv4Address | None = None,
                 ip6_all_nodes_address: ipaddress.IPv6Address | None = None):
        self.id = id
        self.name = name
        self.dhcp_manager = dhcp_manager
        self.netlink_manager = netlink_manager
        self.tags_enum = tags_enum
        self.default_svi_config = default_svi_config
        self.svi_config = svi_config
        self.enforce_eth_address = enforce_eth_address
        self.enforce_ip6_ll_address = enforce_ip6_ll_address
        self.ip4_all_nodes_address = ip4_all_nodes_address
        self.ip6_all_nodes_address = ip6_all_nodes_address

        self.network_devices: dict[str, LXDNetworkDevice] = {}

    @contextlib.contextmanager
    def attributes_transaction(self) -> collections.abc.Iterator[None]:
        attributes = self.__dict__.copy()
        try:
            yield None
        except BaseException:
            self.__dict__ = attributes
            raise

    @staticmethod
    def parse_tags_spec(spec: str, tag_type: type[TTags], instance_name: str) -> frozenset[TTags]:
        results: set[TTags] = set()
        for tag in spec.strip().split():
            try:
                results.add(tag_type[tag])
            except KeyError:
                logging.warning("Instance '{}' has unknown tag '{}'.".format(instance_name, tag))
        return frozenset(results)

    @staticmethod
    def parse_service_spec(spec: str, instance_name: str) -> frozenset[Service]:
        results: set[Service] = set()
        for service in spec.strip().split():
            try:
                results.add(Service.parse(service))
            except ValueError as e:
                logging.warning("Instance '{}' has invalid service specification ('{}'): {}.".format(instance_name, service, e))
        return frozenset(results)

    def reload(self, lxd_instance: pylxd.models.container.Container) -> None:
        logging.debug("Reloading LXD instance '{}'.".format(lxd_instance.name))
        if lxd_instance.name != self.name:
            logging.info("LXD instance '{}' has new name '{}'.".format(self.name, lxd_instance.name))
            self.name = lxd_instance.name
        state = lxd_instance.state()

        # Get global attributes
        try:
            global_tags = self.parse_tags_spec(lxd_instance.expanded_config['user.lxmesh.tags'], self.tags_enum, lxd_instance.name)
        except KeyError:
            global_tags = frozenset()
        try:
            global_in_services = self.parse_service_spec(lxd_instance.expanded_config['user.lxmesh.in_services'], lxd_instance.name)
        except KeyError:
            global_in_services = frozenset()
        try:
            global_out_services = self.parse_service_spec(lxd_instance.expanded_config['user.lxmesh.out_services'], lxd_instance.name)
        except KeyError:
            global_out_services = frozenset()

        # First, remove old network devices, before reconfiguring new ones.
        # This is in case a network device was renamed.
        old_network_devices, self.network_devices = self.network_devices, {}
        for device_name, device_config in lxd_instance.expanded_devices.items():
            if device_config.get('type') != 'nic':
                continue
            if device_config.get('nictype') != 'p2p':
                continue
            if 'user.lxmesh.parent' not in device_config:
                continue
            try:
                network_device = old_network_devices.pop(device_name)
            except KeyError:
                logging.info("LXD instance '{}' has VPC network device '{}'.".format(lxd_instance.name, device_name))
                network_device = LXDNetworkDevice(vpc=device_name,
                                                  dhcp_manager=self.dhcp_manager,
                                                  netlink_manager=self.netlink_manager,
                                                  tags_enum=self.tags_enum,
                                                  default_svi_config=self.default_svi_config,
                                                  svi_config=self.svi_config,
                                                  ip4_all_nodes_address=self.ip4_all_nodes_address,
                                                  ip6_all_nodes_address=self.ip6_all_nodes_address)
            self.network_devices[device_name] = network_device

        with self.dhcp_manager, self.netlink_manager:
            for network_name, network_device in old_network_devices.items():
                logging.info("LXD instance '{}' no longer has VPC network device '{}'.".format(lxd_instance.name, network_name))
                network_device.reset()

            for network_name, network_device in self.network_devices.items():
                device_config = lxd_instance.expanded_devices[network_name]
                svi = device_config['user.lxmesh.parent']
                try:
                    vpc_device = device_config['name']
                except KeyError:
                    logging.warning("Ignoring network device '{}' in LXD instance '{}' because it is not named.".format(network_name, lxd_instance.name))
                    vpc_device = None

                if lxd_instance.status_code == (102, 107):  # Stopped, Stopping
                    logging.log(logging.INFO if network_device.device_name is not None else logging.DEBUG,
                                "LXD instance '{}' is {}.".format(lxd_instance.name, lxd_instance.status.lower()))
                    vpc_network = None
                elif state.network is None or vpc_device is None:
                    logging.log(logging.INFO if network_device.device_name is not None else logging.DEBUG,
                                "LXD instance '{}' does not have a VPC interface.".format(lxd_instance.name))
                    vpc_network = None
                else:
                    logging.debug("LXD instance '{}' has VPC network '{}' connected to interface '{}'.".format(lxd_instance.name, network_name, vpc_device))
                    try:
                        vpc_network = state.network[vpc_device]
                    except KeyError:
                        logging.warning("Instance '{}' state does not contain expected VPC network interface '{}'.".format(lxd_instance.name, vpc_device))
                        vpc_network = None

                if vpc_network is not None:
                    device_name = vpc_network['host_name']
                else:
                    device_name = None

                if vpc_network is not None:
                    device_address = vpc_network['hwaddr']
                    try:
                        expected_address = lxd_instance.config['volatile.{}.hwaddr'.format(network_name)]
                    except KeyError:
                        if self.enforce_eth_address:
                            logging.error("Ignoring network device '{}' in LXD instance '{}' because it does not have an attested ethernet address.".format(network_name, lxd_instance.name))
                            device_address = None
                        else:
                            logging.warning("LXD instance '{}' does not have an attested ethernet address for VPC interface '{}'.".format(lxd_instance.name, network_name))
                    else:
                        if device_address == expected_address:
                            pass
                        elif self.enforce_eth_address:
                            logging.error("LXD instance '{}' has unattested ethernet address for VPC interface '{}': found '{}' and expected '{}'. Connectivity will likely fail.".format(lxd_instance.name, vpc_device, device_address, expected_address))
                            device_address = expected_address
                        else:
                            logging.warning("LXD instance '{}' has unattested ethernet address for VPC interface '{}': found '{}' and expected '{}'.".format(lxd_instance.name, vpc_device, device_address, expected_address))
                else:
                    device_address = None

                try:
                    tags = self.parse_tags_spec(device_config['user.lxmesh.tags'].strip(), self.tags_enum, lxd_instance.name)
                except KeyError:
                    tags = frozenset()

                try:
                    ip4_address = ipaddress.IPv4Address(device_config['user.lxmesh.ipv4.address'])
                except KeyError:
                    ip4_address = None
                except ValueError as e:
                    logging.warning("Instance '{}' has invalid IPv4 address configured ('{}'): {}.".format(lxd_instance.name, device_config['user.lxmesh.ipv4.address'], e))
                    ip4_address = None

                try:
                    ip6_address = ipaddress.IPv6Address(device_config['user.lxmesh.ipv6.address'])
                except KeyError:
                    ip6_address = None
                except ValueError as e:
                    logging.warning("Instance '{}' has invalid IPv6 address configured ('{}'): {}.".format(lxd_instance.name, device_config['user.lxmesh.ipv6.address'], e))
                    ip6_address = None

                if vpc_network is not None:
                    expected_ip6_link_address = ethernet2ipv6eui64(ipaddress.IPv6Network('fe80::/64'), device_address)
                    for address_desc in vpc_network.get('addresses', []):
                        if address_desc['family'] != 'inet6':
                            continue
                        if address_desc['netmask'] != '64':
                            continue
                        address = ipaddress.IPv6Address(address_desc['address'])
                        if address.is_link_local:
                            if address == expected_ip6_link_address:
                                pass
                            elif self.enforce_ip6_ll_address:
                                logging.error("LXD instance '{}' has unattested IPv6 link-local address for VPC interface '{}': found '{}' and expected '{}'. Connectivity will likely fail.".format(lxd_instance.name, vpc_device, address, expected_ip6_link_address))
                                continue
                            else:
                                logging.warning("LXD instance '{}' has unattested IPv6 link-local address for VPC interface '{}': found '{}' and expected '{}'.".format(lxd_instance.name, vpc_device, address, expected_ip6_link_address))
                            ip6_link_address = address
                            break
                    else:
                        ip6_link_address = expected_ip6_link_address
                else:
                    ip6_link_address = None

                try:
                    in_services = self.parse_service_spec(device_config['user.lxmesh.in_services'], lxd_instance.name)
                except KeyError:
                    in_services = frozenset()

                try:
                    out_services = self.parse_service_spec(device_config['user.lxmesh.out_services'], lxd_instance.name)
                except KeyError:
                    out_services = frozenset()

                try:
                    with self.dhcp_manager, self.netlink_manager, network_device.attributes_transaction():
                        network_device.instance_name = lxd_instance.name
                        network_device.svi = svi
                        network_device.device_name = device_name
                        network_device.device_address = device_address
                        network_device.tags = tags | global_tags
                        network_device.ip4_address = ip4_address
                        network_device.ip6_address = ip6_address
                        network_device.ip6_link_address = ip6_link_address
                        network_device.in_services = in_services | global_in_services
                        network_device.out_services = out_services | global_out_services
                except KeyError:
                    logging.critical("Failed to load network '{}' of LXD instance '{}' due to a bug.".format(network_name, lxd_instance.name))
                except ValueError:
                    logging.warning("Failed to load network '{}' of LXD instance '{}' due to a conflict.".format(network_name, lxd_instance.name))
                except Exception:
                    logging.exception("Unexpected exception while loading network '{}' of LXD instance '{}':".format(network_name, lxd_instance.name))

    def reset(self) -> None:
        for network_device in self.network_devices.values():
            network_device.reset()
        self.network_devices.clear()


class LXDMonitor(threading.Thread):
    def __init__(self, command_queue: queue.SimpleQueue[typing.Any]) -> None:
        super().__init__(name="lxd-monitor")

        self.stopped = False
        self.command_queue = command_queue
        self.rd_pipe, self.wr_pipe = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)

        self.poll = select.epoll()
        self.ws_client: NonblockingWSClient | None = None

        self.filters: dict[str, set[str]] = {}
        self.subscriptions: dict[tuple[str, tuple[tuple[str, str], ...]], list[collections.abc.Callable[[dict[str, typing.Any]], None]]] = {}
        self.event_types: set[pylxd.EventType] = set()

    def register_subscription(self, handler: collections.abc.Callable[[dict[str, typing.Any]], None], type: pylxd.EventType, metadata_filters: dict[str, str] = {}) -> None:
        if self.is_alive() or self.stopped:
            raise ValueError("cannot register subscription after monitoring thread is started")
        self.event_types.add(type)
        try:
            if self.filters[type.value] != set(metadata_filters.keys()):
                raise ValueError("different set of attributes already registered for LXD event type '{}'".format(type))
        except KeyError:
            self.filters[type.value] = set(metadata_filters.keys())
        metadata = list(metadata_filters.items())
        metadata.sort()
        self.subscriptions.setdefault((type.value, tuple(metadata)), []).append(handler)

    def start(self) -> None:
        if self.is_alive() or self.stopped:
            raise ValueError("cannot restart LXD monitoring thread")
        self._init_ws_client()
        super().start()

    def stop(self) -> None:
        if not self.stopped:
            self.stopped = True
            try:
                os.write(self.wr_pipe, b'\x00')
            except BlockingIOError:
                pass

    def _init_ws_client(self) -> None:
        try:
            client = pylxd.Client()
            websocket_type = functools.partial(NonblockingWSClient, text_encoding='utf-8', bytes_encoding='utf-8', close_timeout=2)
            ws_client: NonblockingWSClient = client.events(websocket_client=websocket_type, event_types=self.event_types)
            ws_client.connect()
        except (pylxd.exceptions.LXDAPIException, pylxd.exceptions.ClientConnectionFailed, OSError) as e:
            logging.error("Failed to open LXD events socket: {}.".format(e))
        except Exception:
            logging.exception("Unexpected exception while opening LXD events socket:")
        else:
            self.ws_client = ws_client
            self.poll.register(ws_client, select.EPOLLIN | select.EPOLLOUT | select.EPOLLERR | select.EPOLLET)

    def run(self) -> None:
        next_ws_client_hb = time.monotonic() if self.ws_client is not None else float('inf')

        self.poll.register(self.rd_pipe, select.EPOLLIN)
        while not self.stopped or self.ws_client is not None:
            timeout = float('inf')
            now = time.monotonic()

            # Cleanly close LXD events socket if we've been asked to stop.
            if self.stopped:
                ws_client: NonblockingWSClient = self.ws_client  # type: ignore[assignment] # self.ws_client is never None considering loop condition above.
                if ws_client.closed:
                    break
                try:
                    ws_client.close()
                except OSError as e:
                    logging.error("Failed to cleanly close LXD events socket: {}.".format(e.strerror))
                    ws_client.force_close()
                    self.ws_client = None
                    break

            # Check if we need to send a heartbeat.
            if self.ws_client is not None and now >= next_ws_client_hb:
                try:
                    self.ws_client.heartbeat()
                except OSError as e:
                    logging.error("Failed to send heartbeat on LXD events socket: {}.".format(e.strerror))
                    self.ws_client.force_close()
                    self.ws_client = None
                else:
                    next_ws_client_hb = now + 10

            # Reconnect LXD events socket if lost earlier.
            if self.ws_client is None and not self.stopped:
                self._init_ws_client()
                if self.ws_client is not None:
                    next_ws_client_hb = now + 10
                else:
                    timeout = min(timeout, 1.0)
                    next_ws_client_hb = float('inf')
            timeout = min(timeout, next_ws_client_hb - now)

            # Check how long before we forcefully close; close_expected()
            # method also forcefully closes the connection if the timeout
            # elapsed.
            if self.ws_client is not None:
                try:
                    timeout = min(timeout, self.ws_client.close_expected())
                except ValueError:
                    timeout = 0  # Socket may have been closed, reconnect immediately.
                if self.ws_client.closed:
                    self.ws_client = None

            poll_result = self.poll.poll(max(timeout, 0) if not math.isinf(timeout) else None)
            for fd, fd_events in poll_result:
                if fd == self.rd_pipe:
                    try:
                        os.read(self.rd_pipe, 4096)
                    except BlockingIOError:
                        pass
                    continue
                elif self.ws_client is None or fd != self.ws_client.fileno():
                    continue

                if fd_events & select.EPOLLIN:
                    while True:
                        try:
                            message = self.ws_client.recv()
                        except BlockingIOError:
                            break
                        except ValueError:
                            logging.error("Received invalid data on LXD events socket.")
                        except websockets.exceptions.ProtocolError as e:
                            logging.error("Received invalid frames on LXD events socket: {}.".format(e))
                        except OSError as e:
                            logging.error("Failed to receive data from LXD events socket: {}.".format(e.strerror))
                            self.ws_client.force_close()
                            self.ws_client = None
                            break
                        else:
                            try:
                                json_message = json.loads(message)
                            except ValueError:
                                continue
                            type = json_message.get('type')
                            metadata = json_message.get('metadata', {})
                            try:
                                metadata_names = self.filters[type]
                            except KeyError:
                                continue
                            try:
                                metadata_values = list(map(metadata.get, metadata_names))
                            except Exception as e:
                                logging.warning("Failed to get metadata from LXD event message: {}.".format(e))
                                continue
                            else:
                                metadata = list(zip(metadata_names, metadata_values))
                                metadata.sort()
                                metadata = tuple(metadata)
                            try:
                                handlers = self.subscriptions[type, metadata]
                            except KeyError:
                                continue
                            else:
                                self.command_queue.put(LXDEvent(message=json_message, handlers=handlers))
                if fd_events & select.EPOLLOUT:
                    if self.ws_client is not None:
                        try:
                            self.ws_client.send()
                        except OSError as e:
                            logging.exception("Failed to send data to LXD events socket: {}.".format(e.strerror))
                            self.ws_client.force_close()
                            self.ws_client = None
                if fd_events & select.EPOLLERR:
                    if self.ws_client is not None:
                        self.ws_client.force_close()
                        self.ws_client = None


class LXDManager:
    # The lack of a unique persistent identifier makes it impossible to
    # guarantee consistency without perfectly reliable change notifications
    # (which, of course, do not exist). Missed notifications can result in
    # completely incorrect states.  For example, assuming two instances, A and
    # B, identified uniquely using U1 and U2, take the following sequence of
    # operations:
    #   A(U1) renamed to C(U1)
    #   B(U2) renamed to A(U2)
    #   A(U2) renamed to D(U2)
    #   D(U2) attributes changed
    #
    # If the first two operations are missed, the attributes change cannot take
    # effect because the state believes the instance which changed attributes
    # is U1, when it is in fact U2. The problem lies with the fact that that
    # D(U2) may retain an attribute, such as a device name, that the state will
    # have assigned to both B and D.
    #
    # A unique identifier is emulated by storing a generated one in a
    # configuration parameter. However, this is only used as a protection
    # mechanism, as it cannot be guaranteed to exist, nevermind that
    # persistently storing it may fail. Unfortunately, this introduces issues
    # of its own: the storing of the persistent identifier is not guaranteed to
    # operate on the desired instance. Even worse, it seems like the library
    # performs a full PUT, instead of a partial PATCH, and the API does not
    # support ETags. This issue is minimised by storing a newly generated
    # identifier just once per instance lifetime and in quick succession after
    # the instance was retrieved.
    #
    # Ideally, don't rename instances.

    def __init__(self, *,
                 lxd_monitor: LXDMonitor,
                 dhcp_manager: DHCPManager,
                 netlink_manager: NetlinkManager,
                 tags_enum: type[TagsBase],
                 default_svi_config: LXDSVIConfig,
                 svi_config: dict[str, LXDSVIConfig] = {},
                 enforce_eth_address: bool,
                 enforce_ip6_ll_address: bool,
                 id_attribute: str,
                 ip4_all_nodes_address: ipaddress.IPv4Address | None = None,
                 ip6_all_nodes_address: ipaddress.IPv6Address | None = None):
        self.lxd_monitor = lxd_monitor
        self.dhcp_manager = dhcp_manager
        self.netlink_manager = netlink_manager
        self.tags_enum = tags_enum
        self.default_svi_config = default_svi_config
        self.svi_config = svi_config
        self.enforce_eth_address = enforce_eth_address
        self.enforce_ip6_ll_address = enforce_ip6_ll_address
        self.id_attribute = id_attribute
        self.ip4_all_nodes_address = ip4_all_nodes_address
        self.ip6_all_nodes_address = ip6_all_nodes_address

        self.instances: dict[str, LXDInstance] = {}
        self.initialised = False

        self.register_lifecycle_subscription(self._EVT_instance_created, action='instance-created')
        self.register_lifecycle_subscription(self._EVT_instance_deleted, action='instance-deleted')
        self.register_lifecycle_subscription(self._EVT_instance_updated, action='instance-paused')
        self.register_lifecycle_subscription(self._EVT_instance_renamed, action='instance-renamed')
        self.register_lifecycle_subscription(self._EVT_instance_updated, action='instance-restarted')
        self.register_lifecycle_subscription(self._EVT_instance_updated, action='instance-resumed')
        self.register_lifecycle_subscription(self._EVT_instance_updated, action='instance-shutdown')
        self.register_lifecycle_subscription(self._EVT_instance_updated, action='instance-started')
        self.register_lifecycle_subscription(self._EVT_instance_updated, action='instance-stopped')
        self.register_lifecycle_subscription(self._EVT_instance_updated, action='instance-updated')

    def reload(self) -> None:
        try:
            client = pylxd.Client()
            lxd_instances: list[pylxd.models.container.Container] = list(client.containers.all())
        except (pylxd.exceptions.LXDAPIException, pylxd.exceptions.ClientConnectionFailed) as e:
            logging.error("Failed to obtain LXD instances: {}.".format(e))
            return
        except Exception:
            logging.exception("Unexpected exception while loading LXD instances:")
            return

        old_instances: dict[str, LXDInstance] = self.instances or {}
        self.instances = {}
        self.initialised = True
        seen_instance_ids: set[str] = set()
        for lxd_instance in lxd_instances:
            try:
                instance_id = lxd_instance.config[self.id_attribute]
                if instance_id in seen_instance_ids:
                    raise KeyError
            except KeyError:
                instance_id = lxd_instance.config[self.id_attribute] = str(uuid.uuid4())
                try:
                    lxd_instance.save(wait=True)
                except pylxd.exceptions.NotFound:
                    # May have been renamed or deleted in the mean time, drop it.
                    continue
                except Exception as e:
                    logging.warning("Failed to persistently store new instance identifier for '{}': {}; near-real-time synchronisation will be affected.".format(lxd_instance.name, e))
                    instance_id = None
            if instance_id is not None:
                seen_instance_ids.add(instance_id)
            try:
                instance = old_instances.pop(lxd_instance.name)
            except KeyError:
                logging.info("Loaded LXD instance '{}'.".format(lxd_instance.name))
                instance = LXDInstance(id=instance_id,
                                       name=lxd_instance.name,
                                       dhcp_manager=self.dhcp_manager,
                                       netlink_manager=self.netlink_manager,
                                       tags_enum=self.tags_enum,
                                       default_svi_config=self.default_svi_config,
                                       svi_config=self.svi_config,
                                       enforce_eth_address=self.enforce_eth_address,
                                       enforce_ip6_ll_address=self.enforce_ip6_ll_address,
                                       ip4_all_nodes_address=self.ip4_all_nodes_address,
                                       ip6_all_nodes_address=self.ip6_all_nodes_address)
            else:
                instance.id = instance_id
            self.instances[lxd_instance.name] = instance
        for old_instance in old_instances.values():
            logging.info("LXD instance '{}' no longer exists.".format(old_instance.name))
            old_instance.reset()
        for lxd_instance in lxd_instances:
            try:
                instance = self.instances[lxd_instance.name]
            except KeyError:
                continue
            try:
                instance.reload(lxd_instance)
            except KeyError:
                logging.critical("Failed to load instance '{}' due to a bug.".format(lxd_instance.name))
            except ValueError:
                logging.warning("Failed to load instance '{}' due to a conflict.".format(lxd_instance.name))
            except Exception:
                logging.exception("Unexpected exception while reloading LXD instance '{}':".format(lxd_instance.name))
                continue

    def register_lifecycle_subscription(self, handler: collections.abc.Callable[[str, dict[str, typing.Any]], None], action: str) -> None:
        if isinstance(handler, types.MethodType):
            handler_ref = weakref.WeakMethod(handler)
        else:
            handler_ref = weakref.ref(handler)
        handler = functools.partial(self.process_lifecycle_event, handler_ref)
        self.lxd_monitor.register_subscription(handler, pylxd.EventType.Lifecycle, metadata_filters={'action': action})

    @staticmethod
    def process_lifecycle_event(handler_ref: weakref.ref[collections.abc.Callable[[str, dict[str, typing.Any]], None]], message: dict[str, typing.Any]) -> None:
        metadata = message.get('metadata', {})
        instance = metadata.get('source')
        if not instance:
            logging.warning("Received invalid LXD event.")
            return

        instance = instance.rsplit('/', 1)[-1]

        handler = handler_ref()
        if handler is None:
            logging.critical("Lost reference to event handler.")
            return
        try:
            handler(instance, metadata)
        except LXDError as e:
            logging.error(e.message_sentence)
        except Exception:
            logging.exception("Unexpected exception while executing LXD event handler:")

    def _EVT_instance_created(self, name: str, metadata: dict[str, typing.Any]) -> None:
        if not self.initialised:
            return
        if name in self.instances:
            # A reload() may have already executed or we are out of sync.
            return
        logging.debug("Detected new LXD instance '{}'.".format(name))
        try:
            client = pylxd.Client()
            lxd_instance: pylxd.models.container.Container = client.containers.get(name)
        except pylxd.exceptions.NotFound:
            # May have been renamed or deleted in the mean time.
            return
        except (pylxd.exceptions.LXDAPIException, pylxd.exceptions.ClientConnectionFailed) as e:
            raise LXDError("failed to obtain LXD instance '{}': {}".format(name, e))
        try:
            instance_id = lxd_instance.config[self.id_attribute]
        except KeyError:
            instance_id = None
            lxd_instance.config[self.id_attribute] = str(uuid.uuid4())
            try:
                lxd_instance.save(wait=True)
            except pylxd.exceptions.NotFound:
                # May have been renamed or deleted in the mean time, drop it.
                return
            except (pylxd.exceptions.LXDAPIException, pylxd.exceptions.ClientConnectionFailed) as e:
                logging.warning("Failed to persistently store new instance identifier for '{}': {}; near-real-time synchronisation will be affected.".format(name, e))
            except Exception:
                logging.exception("Unexpected exception while trying to store persistent identifier:")
            else:
                instance_id = lxd_instance.config[self.id_attribute]
        logging.info("Loaded LXD instance '{}'.".format(lxd_instance.name))
        instance = LXDInstance(id=instance_id,
                               name=lxd_instance.name,
                               dhcp_manager=self.dhcp_manager,
                               netlink_manager=self.netlink_manager,
                               tags_enum=self.tags_enum,
                               default_svi_config=self.default_svi_config,
                               svi_config=self.svi_config,
                               enforce_eth_address=self.enforce_eth_address,
                               enforce_ip6_ll_address=self.enforce_ip6_ll_address,
                               ip4_all_nodes_address=self.ip4_all_nodes_address,
                               ip6_all_nodes_address=self.ip6_all_nodes_address)
        try:
            instance.reload(lxd_instance)
        except KeyError:
            logging.critical("Failed to load instance '{}' due to a bug.".format(name))
        except ValueError:
            logging.warning("Failed to load new instance '{}': conflict or data is out of sync.".format(name))
        self.instances[name] = instance

    def _EVT_instance_deleted(self, name: str, metadata: dict[str, typing.Any]) -> None:
        if not self.initialised:
            return
        try:
            instance = self.instances[name]
        except KeyError:
            # May have been deleted or renamed and a reload() already executed;
            # or we are out of sync.
            return
        logging.debug("Detected LXD instance '{}' was deleted.".format(name))
        if instance.id is None:
            logging.warning("Ignoring deletion of instance '{}' without persistent identifier.".format(name))
            return
        try:
            client = pylxd.Client()
            lxd_instance: pylxd.models.container.Container = client.containers.get(name)
        except pylxd.exceptions.NotFound:
            logging.info("LXD instance '{}' no longer exists.".format(instance.name))
            instance.reset()
            return
        except (pylxd.exceptions.LXDAPIException, pylxd.exceptions.ClientConnectionFailed) as e:
            raise LXDError("failed to obtain LXD instance '{}': {}".format(name, e))
        else:
            # Well, it still exists?!
            if instance.id == lxd_instance.config.get(self.id_attribute, None):
                try:
                    instance.reload(lxd_instance)
                except KeyError:
                    logging.critical("Failed to update instance '{}' due to a bug.".format(name))
                except ValueError:
                    logging.warning("Failed to update instance '{}': conflict or data is out of sync.".format(name))
            else:
                logging.warning("Ignoring deletion of instance '{}' that doesn't match known identifier (data out of sync).".format(name))

    def _EVT_instance_renamed(self, name: str, metadata: dict[str, typing.Any]) -> None:
        if not self.initialised:
            return
        if name in self.instances:
            # A reload() may have already executed or we are out of sync.
            return
        old_name = metadata['context']['old_name']
        logging.debug("Detected LXD instance '{}' was renamed as '{}'.".format(old_name, name))
        try:
            instance = self.instances.pop(old_name)
        except KeyError:
            # May have been deleted or renamed and a reload() already executed.
            return
        self.instances[name] = instance

    def _EVT_instance_updated(self, name: str, metadata: dict[str, typing.Any]) -> None:
        if not self.initialised:
            return
        try:
            instance = self.instances[name]
        except KeyError:
            # May have been deleted or renamed and a reload() already executed;
            # or we are out of sync.
            return
        if instance.id is None:
            logging.warning("Ignoring change to instance '{}' without persistent identifier.".format(name))
            return
        logging.debug("Detected LXD instance '{}' was updated.".format(name))
        try:
            client = pylxd.Client()
            lxd_instance: pylxd.models.container.Container = client.containers.get(name)
        except pylxd.exceptions.NotFound:
            # May have been renamed or deleted in the mean time, drop it.
            return
        except (pylxd.exceptions.LXDAPIException, pylxd.exceptions.ClientConnectionFailed) as e:
            raise LXDError("failed to obtain LXD instance '{}': {}".format(name, e))
        else:
            if instance.id == lxd_instance.config.get(self.id_attribute, None):
                try:
                    instance.reload(lxd_instance)
                except KeyError:
                    logging.critical("Failed to update instance '{}' due to a bug.".format(name))
                except ValueError:
                    logging.warning("Failed to update instance '{}': conflict or data is out of sync.".format(name))
            else:
                logging.warning("Ignoring change to instance '{}' that doesn't match known identifier (data out of sync).".format(name))

    _EVT_instance_stopped = _EVT_instance_updated
    _EVT_instance_started = _EVT_instance_updated
    _EVT_instance_shutdown = _EVT_instance_updated
    _EVT_instance_restarted = _EVT_instance_updated
