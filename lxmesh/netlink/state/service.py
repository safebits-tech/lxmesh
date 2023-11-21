from __future__ import annotations

__all__ = ['ServiceState']

import collections.abc
import errno
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


class ServiceState(StateObject[NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext]):
    direction:  typing.Literal['in', 'out']
    device:     str
    protocol:   typing.Literal['sctp', 'tcp', 'udp']
    port:       int

    @classmethod
    def init(cls, context: NetlinkInitialiseContext) -> None:
        for set_name in [str(NFTablesSets.in_services), str(NFTablesSets.out_services)]:
            context.register_nf_subscription(cls.event_set, pyroute2.netlink.nfnetlink.NFNLGRP_NFTABLES,
                                             family=NFProto.BRIDGE, operation=(pyroute2.netlink.nfnetlink.NFNL_SUBSYS_NFTABLES << 8) | nftsocket.NFT_MSG_NEWSET,
                                             attribute_filters=dict(NFTA_SET_TABLE=context.table_name, NFTA_SET_NAME=set_name))
            attribute_filters = {}
            attribute_filters[NFTablesRaw.NFTA_SET_ELEM_LIST_TABLE] = context.table_name
            attribute_filters['NFTA_SET_ELEM_LIST_SET'] = set_name
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
        direction = {
            str(NFTablesSets.in_services):  'in',
            str(NFTablesSets.out_services): 'out',
        }[set_name]
        logging.debug("Forcing re-addition of all corresponding netlink set elements because set 'bridge {} {}' was re-created.".format(context.table_name, set_name))
        active_objects: deque[ServiceState] = deque()
        while True:
            try:
                obj = context.active.popitem_by_type(cls)
            except KeyError:
                break
            else:
                if obj.direction == direction:
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
        direction = {
            str(NFTablesSets.in_services):  'in',
            str(NFTablesSets.out_services): 'out',
        }[set_name]
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
                device, protocol, port = struct.unpack('@16sII', key)
            except struct.error:
                raise NetlinkError("unexpected length of key in services set 'bridge {} {}': {}".format(context.table_name, set_name, len(key))) from None
            else:
                device = device.rstrip(b'\x00').decode('utf-8')
            try:
                protocol = {
                    socket.IPPROTO_SCTP:    'sctp',
                    socket.IPPROTO_TCP:     'tcp',
                    socket.IPPROTO_UDP:     'udp',
                }[protocol]
            except KeyError:
                logging.warning("Element in set 'bridge {} {}' for {} services has unknown protocol: {}.".format(context.table_name, set_name, direction, protocol))
                continue
            if not (0 < port < 2**16):
                logging.warning("Element in set 'bridge {} {}' for {} services has invalid port: {}.".format(context.table_name, set_name, direction, port))
                continue
            else:
                port = socket.ntohs(port)

            obj = cls(direction=direction, device=device, protocol=protocol, port=port)
            active_obj = context.active.get(obj)
            if active_obj is None:
                if elements['header']['type'] & 0xFF == nftsocket.NFT_MSG_NEWSETELEM and not context.pending_add.contains_exact(obj) and not context.pending_remove.contains_need_not_match(obj):
                    logging.debug("Marking netlink set element '{}.{}.{}' in 'bridge {} {}' for removal because it is not wanted.".format(device, protocol, port, context.table_name, set_name))
                    context.pending_remove.add(obj)
                return

            if elements['header']['type'] & 0xFF == nftsocket.NFT_MSG_NEWSETELEM:
                if obj != active_obj:
                    logging.debug("Forcing re-addition of netlink set element '{}.{}.{}' in 'bridge {} {}'.".format(device, protocol, port, context.table_name, set_name))
                    context.active.remove_if_exact(active_obj)
                    context.pending_add.add(active_obj)
            elif elements['header']['type'] & 0xFF == nftsocket.NFT_MSG_DELSETELEM:
                if obj == active_obj:
                    logging.debug("Forcing re-addition of netlink set element '{}.{}.{}' in 'bridge {} {}'.".format(device, protocol, port, context.table_name, set_name))
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
                logging.error("Failed to load services from netfilter set '{}': {} ({}).".format(set_name, os.strerror(e.code), e.code))

        results_in = context.nft_raw.get_elements(NFProto.BRIDGE, context.table_name, str(NFTablesSets.in_services))
        results_out = context.nft_raw.get_elements(NFProto.BRIDGE, context.table_name, str(NFTablesSets.out_services))
        results_combined = itertools.chain(
            zip(itertools.repeat(('in', NFTablesSets.in_services)),
                handle_netlink_error(results_in, 'bridge {} {}'.format(context.table_name, NFTablesSets.in_services))),
            zip(itertools.repeat(('out', NFTablesSets.out_services)),
                handle_netlink_error(results_out, 'bridge {} {}'.format(context.table_name, NFTablesSets.out_services))),
        )
        for (direction, set_name), (key, value) in results_combined:
            try:
                device, protocol, port = struct.unpack('@16sII', key)
            except struct.error:
                logging.error("Unexpected length of key in services set 'bridge {} {}': {}.".format(context.table_name, set_name, len(key)))
            else:
                device = device.rstrip(b'\x00').decode('utf-8')
            try:
                protocol = {
                    socket.IPPROTO_SCTP:    'sctp',
                    socket.IPPROTO_TCP:     'tcp',
                    socket.IPPROTO_UDP:     'udp',
                }[protocol]
            except KeyError:
                logging.warning("Element in set 'bridge {} {}' for {} services has unknown protocol: {}.".format(context.table_name, set_name, direction, protocol))
                continue
            if not (0 < port < 2**16):
                logging.warning("Element iin set 'bridge {} {}' for {} services has invalid port: {}.".format(context.table_name, set_name, direction, port))
                continue
            else:
                port = socket.ntohs(port)
            obj = cls(direction=direction, device=device, protocol=protocol, port=port)
            try:
                context.pending_add.remove_if_exact(obj)
            except KeyError:
                logging.debug("Marking netlink set element '{}.{}.{}' in 'bridge {} {}' for removal because it is not wanted.".format(device, protocol, port, context.table_name, set_name))
                context.pending_remove.add(obj)
            else:
                logging.debug("Marking netlink set element '{}.{}.{}' in 'bridge {} {}' as active.".format(device, protocol, port, context.table_name, set_name))
                context.active.add(obj)

    def add(self, context: NetlinkOperationContext) -> None:
        try:
            encoded_device = self.device.encode('utf-8')
            if len(encoded_device) > 15:
                raise NetlinkError("failed to add service because device name exceeds 15 characters: {}".format(self.device))
            try:
                protocol = {
                    'sctp': socket.IPPROTO_SCTP,
                    'tcp':  socket.IPPROTO_TCP,
                    'udp':  socket.IPPROTO_UDP,
                }[self.protocol]
            except KeyError:
                raise NetlinkError("failed to add service with unknown protocol '{}'".format(self.protocol)) from None
            key = struct.pack('@16sII', encoded_device, protocol, socket.htons(self.port))
            try:
                set_name = {
                    'in':   str(NFTablesSets.in_services),
                    'out':  str(NFTablesSets.out_services),
                }[self.direction]
            except KeyError:
                raise NetlinkError("failed to add service with unknown direction '{}'".format(self.direction)) from None
            context.nft_raw.set_element(NFProto.BRIDGE, context.table_name, set_name, key, create=True, update=True)
        except pyroute2.NetlinkError as e:
            raise NetlinkError("failed to add {} service '{}/{}' for interface '{}': {} ({})".format(self.direction, self.protocol, self.port, self.device, os.strerror(e.code), e.code)) from None
        else:
            logging.info("Added {} service '{}/{}' for interface '{}'.".format(self.direction, self.protocol, self.port, self.device))

    # FIXME: annotate 'old' with typing.Self in Python 3.11+.
    def modify(self, context: NetlinkOperationContext, old: ServiceState) -> None:
        try:
            encoded_device = self.device.encode('utf-8')
            if len(encoded_device) > 15:
                raise NetlinkError("failed to update tag because device name exceeds 15 characters: {}".format(self.device))
            try:
                protocol = {
                    'sctp': socket.IPPROTO_SCTP,
                    'tcp':  socket.IPPROTO_TCP,
                    'udp':  socket.IPPROTO_UDP,
                }[self.protocol]
            except KeyError:
                raise NetlinkError("failed to update service with unknown protocol '{}'".format(self.protocol)) from None
            key = struct.pack('@16sII', encoded_device, protocol, socket.htons(self.port))
            try:
                set_name = {
                    'in':   str(NFTablesSets.in_services),
                    'out':  str(NFTablesSets.out_services),
                }[self.direction]
            except KeyError:
                raise NetlinkError("failed to update service with unknown direction '{}'".format(self.direction)) from None
            context.nft_raw.set_element(NFProto.BRIDGE, context.table_name, set_name, key, create=False, update=True)
        except pyroute2.NetlinkError as e:
            raise NetlinkError("failed to update {} service '{}/{}' for interface '{}': {} ({})".format(self.direction, self.protocol, self.port, self.device, os.strerror(e.code), e.code)) from None
        else:
            logging.info("Updated {} service '{}/{}' for interface '{}'.".format(self.direction, self.protocol, self.port, self.device))

    def delete(self, context: NetlinkOperationContext) -> None:
        try:
            encoded_device = self.device.encode('utf-8')
            if len(encoded_device) > 15:
                raise NetlinkError("failed to delete service because device name exceeds 15 characters: {}".format(self.device))
            try:
                protocol = {
                    'sctp': socket.IPPROTO_SCTP,
                    'tcp':  socket.IPPROTO_TCP,
                    'udp':  socket.IPPROTO_UDP,
                }[self.protocol]
            except KeyError:
                raise NetlinkError("failed to delete service with unknown protocol '{}'".format(self.protocol)) from None
            key = struct.pack('@16sII', encoded_device, protocol, socket.htons(self.port))
            try:
                set_name = {
                    'in':   str(NFTablesSets.in_services),
                    'out':  str(NFTablesSets.out_services),
                }[self.direction]
            except KeyError:
                raise NetlinkError("failed to delete service with unknown direction '{}'".format(self.direction)) from None
            context.nft_raw.del_element(NFProto.BRIDGE, context.table_name, set_name, key)
        except pyroute2.NetlinkError as e:
            raise NetlinkError("failed to delete {} service '{}/{}' for interface '{}': {} ({})".format(self.direction, self.protocol, self.port, self.device, os.strerror(e.code), e.code)) from None
        else:
            logging.info("Deleted {} service '{}/{}' for interface '{}'.".format(self.direction, self.protocol, self.port, self.device))
