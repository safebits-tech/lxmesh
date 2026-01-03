from __future__ import annotations

__all__ = ['MarkState']

import errno
import logging
import os
import struct
import typing

import pyroute2  # type: ignore[import-untyped]
import pyroute2.netlink  # type: ignore[import-untyped]
import pyroute2.netlink.nfnetlink  # type: ignore[import-untyped]
from pyroute2.netlink.nfnetlink import nftsocket

from lxmesh.netlink.constants import NFTablesSets
from lxmesh.netlink.exceptions import NetlinkError
from lxmesh.netlink.nftables import NFProto
from lxmesh.netlink.state import NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext
from lxmesh.state import StateObject


class MarkState(StateObject[NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext]):
    device: str
    mark:   int = StateObject.field(key=False)

    @classmethod
    def init(cls, context: NetlinkInitialiseContext) -> None:
        context.register_nf_subscription(cls.event_set, pyroute2.netlink.nfnetlink.NFNLGRP_NFTABLES,
                                         family=NFProto.BRIDGE, operation=(pyroute2.netlink.nfnetlink.NFNL_SUBSYS_NFTABLES << 8) | nftsocket.NFT_MSG_NEWSET,
                                         attribute_filters=dict(NFTA_SET_TABLE=context.table_name, NFTA_SET_NAME=str(NFTablesSets.marks)))
        attribute_filters = {}
        attribute_filters['NFTA_SET_ELEM_LIST_TABLE'] = context.table_name
        attribute_filters['NFTA_SET_ELEM_LIST_SET'] = str(NFTablesSets.marks)
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
        logging.debug("Forcing re-addition of all corresponding netlink map elements because map 'bridge {} {}' was re-created.".format(context.table_name, NFTablesSets.marks))
        while True:
            try:
                obj = context.active.popitem_by_type(cls)
            except KeyError:
                break
            else:
                context.pending_add.add(obj)

    @classmethod
    def event_elements(cls, context: NetlinkEventContext, elements: pyroute2.netlink.nlmsg) -> None:
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
            value_attr = element.get_attr('NFTA_SET_ELEM_DATA')
            if value_attr is None:
                raise NetlinkError("expected 'bridge {} {}' to be a map".format(context.table_name, NFTablesSets.marks))
            value = value_attr.get_attr('NFTA_DATA_VALUE')
            if value is None:
                continue
            try:
                device, = struct.unpack('@16s', key)
            except struct.error:
                raise NetlinkError("unexpected length of key in map 'bridge {} {}': {}".format(context.table_name, NFTablesSets.marks, len(key))) from None
            else:
                device = device.rstrip(b'\x00').decode('utf-8')
            try:
                mark, = struct.unpack('@I', value)
            except struct.error:
                raise NetlinkError("unexpected length of value in map 'bridge {} {}': {}".format(context.table_name, NFTablesSets.marks, len(value))) from None

            obj = cls(device=device, mark=mark)
            active_obj = context.active.get(obj)
            if active_obj is None:
                if elements['header']['type'] & 0xFF == nftsocket.NFT_MSG_NEWSETELEM and not context.pending_add.contains_exact(obj) and not context.pending_remove.contains_need_not_match(obj):
                    logging.debug("Marking netlink map element '{}:0x{:08X}' in 'bridge {} {}' for removal because it is not wanted.".format(device, mark, context.table_name, NFTablesSets.marks))
                    context.pending_remove.add(obj)
                return

            if elements['header']['type'] & 0xFF == nftsocket.NFT_MSG_NEWSETELEM:
                if obj != active_obj:
                    logging.debug("Forcing re-addition of netlink map element '{}:0x{:08X}' in 'bridge {} {}'.".format(device, mark, context.table_name, NFTablesSets.marks))
                    context.active.remove_if_exact(active_obj)
                    context.pending_add.add(active_obj)
            elif elements['header']['type'] & 0xFF == nftsocket.NFT_MSG_DELSETELEM:
                if obj == active_obj:
                    # It doesn't seem possible to atomically replace a set
                    # element, which means that an update will effectively
                    # trigger a NFT_MSG_DELSETELEM event, even if the value is
                    # the same. Therefore, we cannot react to these events. The
                    # problem only occurs for maps (i.e. sets with values).
                    logging.debug("Ignoring removal of netlink map element '{}:0x{:08X}' in 'bridge {} {}' because of kernel limitations.".format(device, mark, context.table_name, NFTablesSets.marks))

    @classmethod
    def load(cls, context: NetlinkLoadContext) -> None:
        try:
            for key, value in context.nft_raw.get_elements(NFProto.BRIDGE, context.table_name, str(NFTablesSets.marks)):
                if value is None:
                    raise NetlinkError("expected 'bridge {} {}' to be a map".format(context.table_name, NFTablesSets.marks))
                try:
                    device, = struct.unpack('@16s', key)
                except struct.error:
                    raise NetlinkError("unexpected length of key in map 'bridge {} {}': {}".format(context.table_name, NFTablesSets.marks, len(key))) from None
                else:
                    device = device.rstrip(b'\x00').decode('utf-8')
                try:
                    mark, = struct.unpack('@I', value)
                except struct.error:
                    raise NetlinkError("unexpected length of value in map 'bridge {} {}': {}".format(context.table_name, NFTablesSets.marks, len(value))) from None
                obj = cls(device=device, mark=mark)
                try:
                    context.pending_add.remove_if_exact(obj)
                except KeyError:
                    logging.debug("Marking netlink map element '{}:0x{:08X}' in 'bridge {} {}' for removal because it is not wanted.".format(device, mark, context.table_name, NFTablesSets.marks))
                    context.pending_remove.add(obj)
                else:
                    logging.debug("Marking netlink map element '{}:0x{:08X}' in 'bridge {} {}' as active.".format(device, mark, context.table_name, NFTablesSets.marks))
                    context.active.add(obj)
        except pyroute2.NetlinkError as e:
            if e.code == errno.ENOENT:
                # Ignore non-existent table or set, as it will be created.
                return
            raise NetlinkError("failed to load marks from netfilter map 'bridge {} {}': {} ({})".format(context.table_name, NFTablesSets.marks, os.strerror(e.code), e.code)) from None

    def add(self, context: NetlinkOperationContext) -> None:
        try:
            encoded_device = self.device.encode('utf-8')
            if len(encoded_device) > 15:
                raise NetlinkError("failed to add mark because device name exceeds 15 characters: {}".format(self.device))
            key = struct.pack('@16s', encoded_device)
            value = struct.pack('@I', self.mark)
            context.nft_raw.set_element(NFProto.BRIDGE, context.table_name, str(NFTablesSets.marks), key, value, create=True, update=True)
        except pyroute2.NetlinkError as e:
            raise NetlinkError("failed to add marks for interface '{}': {} ({})".format(self.device, os.strerror(e.code), e.code)) from None
        else:
            logging.info("Added netfilter mark '{}' for interface '{}'.".format(self.mark, self.device))

    def modify(self, context: NetlinkOperationContext, old: typing.Self) -> None:
        try:
            encoded_device = self.device.encode('utf-8')
            if len(encoded_device) > 15:
                raise NetlinkError("failed to update mark because device name exceeds 15 characters: {}".format(self.device))
            key = struct.pack('@16s', encoded_device)
            value = struct.pack('@I', self.mark)
            context.nft_raw.set_element(NFProto.BRIDGE, context.table_name, str(NFTablesSets.marks), key, value, create=False, update=True)
        except pyroute2.NetlinkError as e:
            raise NetlinkError("failed to update marks for interface '{}': {} ({})".format(self.device, os.strerror(e.code), e.code)) from None
        else:
            logging.info("Replaced netfilter mark '{}' for interface '{}' with '{}'.".format(old.mark, self.device, self.mark))

    def delete(self, context: NetlinkOperationContext) -> None:
        try:
            encoded_device = self.device.encode('utf-8')
            if len(encoded_device) > 15:
                raise NetlinkError("failed to delete mark because device name exceeds 15 characters: {}".format(self.device))
            key = struct.pack('@16s', encoded_device)
            context.nft_raw.del_element(NFProto.BRIDGE, context.table_name, str(NFTablesSets.marks), key)
        except pyroute2.NetlinkError as e:
            raise NetlinkError("failed to delete mark for interface '{}': {} ({})".format(self.device, os.strerror(e.code), e.code)) from None
        else:
            logging.info("Deleted netfilter mark '{}' for interface '{}'.".format(self.mark, self.device))
