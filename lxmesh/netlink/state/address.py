from __future__ import annotations

__all__ = ['ValidatedAddressState']

import collections.abc
import errno
import ipaddress
import itertools
import logging
import os
import socket
import struct
import typing
from collections import deque

import pyroute2  # type: ignore # No stubs
import pyroute2.netlink  # type: ignore # No stubs
import pyroute2.netlink.nfnetlink  # type: ignore # No stubs
from pyroute2.netlink.nfnetlink import nftsocket

from lxmesh.netlink.constants import NFTablesSets
from lxmesh.netlink.exceptions import NetlinkError
from lxmesh.netlink.nftables import NFProto, NFTablesRaw
from lxmesh.netlink.state import NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext
from lxmesh.state import StateObject


T = typing.TypeVar('T')


class ValidatedAddressState(StateObject[NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext]):
    device: str
    family: typing.Literal[socket.AF_BRIDGE, socket.AF_INET, socket.AF_INET6]  # type: ignore # FIXME: this is going to work at one point (mypy >= 1.6?).
    address: ipaddress.IPv4Address | ipaddress.IPv6Address | str

    @classmethod
    def init(cls, context: NetlinkInitialiseContext) -> None:
        for set_name in [NFTablesSets.eth_addresses, NFTablesSets.ip4_addresses, NFTablesSets.ip6_addresses]:
            context.register_nf_subscription(cls.event_set, pyroute2.netlink.nfnetlink.NFNLGRP_NFTABLES,
                                             family=NFProto.BRIDGE, operation=(pyroute2.netlink.nfnetlink.NFNL_SUBSYS_NFTABLES << 8) | nftsocket.NFT_MSG_NEWSET,
                                             attribute_filters=dict(NFTA_SET_TABLE=context.table_name, NFTA_SET_NAME=str(set_name)))
            attribute_filters = {}
            attribute_filters[NFTablesRaw.NFTA_SET_ELEM_LIST_TABLE] = context.table_name
            attribute_filters['NFTA_SET_ELEM_LIST_SET'] = str(set_name)
            context.register_nf_subscription(cls.event_elements, pyroute2.netlink.nfnetlink.NFNLGRP_NFTABLES,
                                             family=NFProto.BRIDGE, operation=(pyroute2.netlink.nfnetlink.NFNL_SUBSYS_NFTABLES << 8) | nftsocket.NFT_MSG_NEWSETELEM,
                                             attribute_filters=attribute_filters)
            context.register_nf_subscription(cls.event_elements, pyroute2.netlink.nfnetlink.NFNLGRP_NFTABLES,
                                             family=NFProto.BRIDGE, operation=(pyroute2.netlink.nfnetlink.NFNL_SUBSYS_NFTABLES << 8) | nftsocket.NFT_MSG_DELSETELEM,
                                             attribute_filters=attribute_filters)

    @classmethod
    def event_set(cls, context: NetlinkEventContext, set: pyroute2.netlink.nlmsg) -> None:
        if set['header']['type'] & 0xFF != nftsocket.NFT_MSG_NEWSET:
            return
        set_name = set.get_attr('NFTA_SET_NAME')
        if set_name is None:
            return
        logging.debug("Forcing re-addition of all corresponding netlink set elements because set 'bridge {} {}' was re-created.".format(context.table_name, set_name))
        family = {
            str(NFTablesSets.eth_addresses):    socket.AF_BRIDGE,
            str(NFTablesSets.ip4_addresses):    socket.AF_INET,
            str(NFTablesSets.ip6_addresses):    socket.AF_INET6,
        }[set_name]
        # FIXME: annotate with typing.Self in Python 3.11+.
        active_objects: deque[ValidatedAddressState] = deque()
        while True:
            try:
                obj = context.active.popitem_by_type(cls)
            except KeyError:
                break
            else:
                if obj.family == family:
                    context.pending_add.add(obj)
                else:
                    active_objects.append(obj)
        while active_objects:
            obj = active_objects.popleft()
            context.active.add(obj)

    @classmethod
    def event_elements(cls, context: NetlinkEventContext, elements: pyroute2.netlink.nlmsg) -> None:
        set_name = elements.get_attr('NFTA_SET_ELEM_LIST_SET')
        if set_name is None:
            return
        family = {
            str(NFTablesSets.eth_addresses):    socket.AF_BRIDGE,
            str(NFTablesSets.ip4_addresses):    socket.AF_INET,
            str(NFTablesSets.ip6_addresses):    socket.AF_INET6,
        }[set_name]
        format = {
            socket.AF_BRIDGE:   '@16s6s2x',
            socket.AF_INET:     '@16s4s',
            socket.AF_INET6:    '@16s16s',
        }[family]
        element_list = elements.get_attr('NFTA_SET_ELEM_LIST_ELEMENTS')
        if element_list is None:
            return
        for element in element_list:
            key_attr = element.get_attr('NFTA_SET_ELEM_KEY')
            if key_attr is None:
                continue
            key = key_attr.get_attr('NFTA_DATA_VALUE')
            if key is None:
                continue
            try:
                device, address = struct.unpack(format, key)
            except struct.error:
                raise NetlinkError("unexpected length of key in validated addresses set 'bridge {} {}': {}".format(context.table_name, set_name, len(key))) from None
            else:
                device = device.rstrip(b'\x00').decode('utf-8')
            match family:
                case socket.AF_BRIDGE:
                    address = address.hex(':')
                case socket.AF_INET | socket.AF_INET6:
                    try:
                        address = ipaddress.ip_address(address)
                    except ValueError:
                        logging.warning("Invalid IP address: {}.".format(address))
                        continue

            obj = cls(device=device, family=family, address=address)
            active_obj = context.active.get(obj)
            if active_obj is None:
                if elements['header']['type'] & 0xFF == nftsocket.NFT_MSG_NEWSETELEM and not context.pending_add.contains_exact(obj) and not context.pending_remove.contains_need_not_match(obj):
                    logging.debug("Marking netlink set element '{}.{}' in 'bridge {} {}' for removal because it is not wanted.".format(device, address, context.table_name, set_name))
                    context.pending_remove.add(obj)
                return

            if elements['header']['type'] & 0xFF == nftsocket.NFT_MSG_NEWSETELEM:
                if obj != active_obj:
                    logging.debug("Forcing re-addition of netlink set element '{}.{}' in 'bridge {} {}'.".format(device, address, context.table_name, set_name))
                    context.active.remove_if_exact(active_obj)
                    context.pending_add.add(active_obj)
            elif elements['header']['type'] & 0xFF == nftsocket.NFT_MSG_DELSETELEM:
                if obj == active_obj:
                    logging.debug("Forcing re-addition of netlink set element '{}.{}' in 'bridge {} {}'.".format(device, address, context.table_name, set_name))
                    context.active.remove_must_match(active_obj)
                    context.pending_add.add(active_obj)

    @classmethod
    def load(cls, context: NetlinkLoadContext) -> None:
        def handle_netlink_error(iterator: collections.abc.Iterator[T], set_name: str) -> collections.abc.Iterator[T]:
            try:
                yield from iterator
            except pyroute2.NetlinkError as e:
                if e.code == errno.ENOENT:
                    # Ignore non-existent table or set, as it will be created.
                    return
                logging.error("Failed to load validated addresses from netfilter set '{}': {} ({}).".format(set_name, os.strerror(e.code), e.code))

        results_eth = context.nft_raw.get_elements(NFProto.BRIDGE, context.table_name, str(NFTablesSets.eth_addresses))
        results_ip4 = context.nft_raw.get_elements(NFProto.BRIDGE, context.table_name, str(NFTablesSets.ip4_addresses))
        results_ip6 = context.nft_raw.get_elements(NFProto.BRIDGE, context.table_name, str(NFTablesSets.ip6_addresses))
        results_combined = itertools.chain(
            zip(itertools.repeat((socket.AF_BRIDGE, NFTablesSets.eth_addresses)),
                handle_netlink_error(results_eth, 'bridge {} {}'.format(context.table_name, NFTablesSets.eth_addresses))),
            zip(itertools.repeat((socket.AF_INET, NFTablesSets.ip4_addresses)),
                handle_netlink_error(results_ip4, 'bridge {} {}'.format(context.table_name, NFTablesSets.ip4_addresses))),
            zip(itertools.repeat((socket.AF_INET6, NFTablesSets.ip6_addresses)),
                handle_netlink_error(results_ip6, 'bridge {} {}'.format(context.table_name, NFTablesSets.ip6_addresses))),
        )
        for (family, set_name), (key, value) in results_combined:
            format = {
                socket.AF_BRIDGE:   '@16s6s2x',
                socket.AF_INET:     '@16s4s',
                socket.AF_INET6:    '@16s16s',
            }[family]
            try:
                device, address = struct.unpack(format, key)
            except struct.error:
                logging.error("Unexpected length of key in validated addresses set 'bridge {} {}': {}.".format(context.table_name, set_name, len(key)))
            else:
                device = device.rstrip(b'\x00').decode('utf-8')
            match family:
                case socket.AF_BRIDGE:
                    address = address.hex(':')
                case socket.AF_INET | socket.AF_INET6:
                    try:
                        address = ipaddress.ip_address(address)
                    except ValueError:
                        logging.warning("Invalid IP address: {}.".format(address))
                        continue
            obj = cls(device=device, family=family, address=address)
            try:
                context.pending_add.remove_if_exact(obj)
            except KeyError:
                logging.debug("Marking netlink set element '{}.{}' in 'bridge {} {}' for removal because it is not wanted.".format(device, address, context.table_name, set_name))
                context.pending_remove.add(obj)
            else:
                logging.debug("Marking netlink set element '{}.{}' in 'bridge {} {}' as active.".format(device, address, context.table_name, set_name))
                context.active.add(obj)

    def add(self, context: NetlinkOperationContext) -> None:
        encoded_device = self.device.encode('utf-8')
        if len(encoded_device) > 15:
            raise NetlinkError("failed to add validated address because device name exceeds 15 characters: {}".format(self.device))
        key = struct.pack('@16s', encoded_device)
        match self.family:
            case socket.AF_BRIDGE:
                if not isinstance(self.address, str):
                    raise TypeError("ValidatedAddress has invalid family and address combination")
                key += bytes.fromhex(self.address.replace(':', '')) + b'\x00\x00'
            case socket.AF_INET | socket.AF_INET6:
                if not isinstance(self.address, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                    raise TypeError("ValidatedAddress has invalid family and address combination")
                key += self.address.packed
        set_name = {
            socket.AF_BRIDGE:   str(NFTablesSets.eth_addresses),
            socket.AF_INET:     str(NFTablesSets.ip4_addresses),
            socket.AF_INET6:    str(NFTablesSets.ip6_addresses),
        }[self.family]
        try:
            context.nft_raw.set_element(NFProto.BRIDGE, context.table_name, set_name, key, create=True, update=True)
        except pyroute2.NetlinkError as e:
            raise NetlinkError("failed to add validated address '{}' for interface '{}': {} ({})".format(self.address, self.device, os.strerror(e.code), e.code)) from None
        else:
            logging.info("Added validated address '{}' for interface '{}'.".format(self.address, self.device))

    # FIXME: annotate 'old' with typing.Self in Python 3.11+.
    def modify(self, context: NetlinkOperationContext, old: ValidatedAddressState) -> None:
        encoded_device = self.device.encode('utf-8')
        if len(encoded_device) > 15:
            raise NetlinkError("failed to update validated address because device name exceeds 15 characters: {}".format(self.device))
        key = struct.pack('@16s', encoded_device)
        match self.family:
            case socket.AF_BRIDGE:
                if not isinstance(self.address, str):
                    raise TypeError("ValidatedAddress has invalid family and address combination")
                key += bytes.fromhex(self.address.replace(':', '')) + b'\x00\x00'
            case socket.AF_INET | socket.AF_INET6:
                if not isinstance(self.address, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                    raise TypeError("ValidatedAddress has invalid family and address combination")
                key += self.address.packed
        set_name = {
            socket.AF_BRIDGE:   str(NFTablesSets.eth_addresses),
            socket.AF_INET:     str(NFTablesSets.ip4_addresses),
            socket.AF_INET6:    str(NFTablesSets.ip6_addresses),
        }[self.family]
        try:
            context.nft_raw.set_element(NFProto.BRIDGE, context.table_name, set_name, key, create=False, update=True)
        except pyroute2.NetlinkError as e:
            raise NetlinkError("failed to update validated address '{}' for interface '{}': {} ({})".format(self.address, self.device, os.strerror(e.code), e.code)) from None
        else:
            logging.info("Updated validated address '{}' for interface '{}'.".format(self.address, self.device))

    def delete(self, context: NetlinkOperationContext) -> None:
        encoded_device = self.device.encode('utf-8')
        if len(encoded_device) > 15:
            raise NetlinkError("failed to delete validated address because device name exceeds 15 characters: {}".format(self.device))
        key = struct.pack('@16s', encoded_device)
        match self.family:
            case socket.AF_BRIDGE:
                if not isinstance(self.address, str):
                    raise TypeError("ValidatedAddress has invalid family and address combination")
                key += bytes.fromhex(self.address.replace(':', '')) + b'\x00\x00'
            case socket.AF_INET | socket.AF_INET6:
                if not isinstance(self.address, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                    raise TypeError("ValidatedAddress has invalid family and address combination")
                key += self.address.packed
        set_name = {
            socket.AF_BRIDGE:   str(NFTablesSets.eth_addresses),
            socket.AF_INET:     str(NFTablesSets.ip4_addresses),
            socket.AF_INET6:    str(NFTablesSets.ip6_addresses),
        }[self.family]
        try:
            context.nft_raw.del_element(NFProto.BRIDGE, context.table_name, set_name, key)
        except pyroute2.NetlinkError as e:
            raise NetlinkError("failed to delete validated address '{}' for interface '{}': {} ({})".format(self.address, self.device, os.strerror(e.code), e.code)) from None
        else:
            logging.info("Deleted validated address '{}' for interface '{}'.".format(self.address, self.device))
