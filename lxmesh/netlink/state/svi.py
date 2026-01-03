from __future__ import annotations

__all__ = ['SVIState']

import collections.abc
import errno
import ipaddress
import itertools
import logging
import os
import socket
import struct
import typing

import pyroute2  # type: ignore[import-untyped]
import pyroute2.netlink  # type: ignore[import-untyped]
import pyroute2.netlink.nfnetlink  # type: ignore[import-untyped]
import pyroute2.netlink.rtnl  # type: ignore[import-untyped]
from pyroute2.netlink.nfnetlink import nftsocket

from lxmesh.netlink.constants import NFTablesSets
from lxmesh.netlink.exceptions import NetlinkError
from lxmesh.netlink.nftables import NFProto
from lxmesh.netlink.state import NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext
from lxmesh.netlink.state.mdb import MDBEntryState
from lxmesh.netlink.state.vxlan import VXLANState
from lxmesh.state import StateObject


T = typing.TypeVar('T')


class SVIState(StateObject[NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext]):
    name:   str

    @classmethod
    def init(cls, context: NetlinkInitialiseContext) -> None:
        context.register_rt_subscription(cls.event_link_svi, pyroute2.netlink.rtnl.RTNLGRP_LINK,
                                         family=socket.AF_UNSPEC, event='RTM_NEWLINK')
        context.register_rt_subscription(cls.event_link_svi, pyroute2.netlink.rtnl.RTNLGRP_LINK,
                                         family=socket.AF_UNSPEC, event='RTM_DELLINK')
        context.register_rt_subscription(cls.event_link_vxlan, pyroute2.netlink.rtnl.RTNLGRP_LINK,
                                         family=socket.AF_UNSPEC, event='RTM_NEWLINK')
        context.register_rt_subscription(cls.event_link_vxlan, pyroute2.netlink.rtnl.RTNLGRP_LINK,
                                         family=socket.AF_UNSPEC, event='RTM_DELLINK')
        for family, set_name in itertools.product([NFProto.BRIDGE, NFProto.INET],
                                                  [str(NFTablesSets.svis), str(NFTablesSets.multicast_svis)]):
            context.register_nf_subscription(cls.event_set, pyroute2.netlink.nfnetlink.NFNLGRP_NFTABLES,
                                             family=family, operation=(pyroute2.netlink.nfnetlink.NFNL_SUBSYS_NFTABLES << 8) | nftsocket.NFT_MSG_NEWSET,
                                             attribute_filters=dict(NFTA_SET_TABLE=context.table_name, NFTA_SET_NAME=set_name))
            attribute_filters = {}
            attribute_filters['NFTA_SET_ELEM_LIST_TABLE'] = context.table_name
            attribute_filters['NFTA_SET_ELEM_LIST_SET'] = set_name
            context.register_nf_subscription(cls.event_elements, pyroute2.netlink.nfnetlink.NFNLGRP_NFTABLES,
                                             family=family, operation=(pyroute2.netlink.nfnetlink.NFNL_SUBSYS_NFTABLES << 8) | nftsocket.NFT_MSG_NEWSETELEM,
                                             attribute_filters=attribute_filters)
            context.register_nf_subscription(cls.event_elements, pyroute2.netlink.nfnetlink.NFNLGRP_NFTABLES,
                                             family=family, operation=(pyroute2.netlink.nfnetlink.NFNL_SUBSYS_NFTABLES << 8) | nftsocket.NFT_MSG_DELSETELEM,
                                             attribute_filters=attribute_filters)

    @classmethod
    def event_link_svi(cls, context: NetlinkEventContext, svi_interface: pyroute2.netlink.nlmsg) -> None:
        # We only care about SVIs that have a name (is there such a thing as an
        # interface without a name?!).
        svi_name = svi_interface.get_attr('IFLA_IFNAME')
        if svi_name is None:
            return

        try:
            svi = context.svi_map[svi_name]
        except KeyError:
            return

        obj = cls(name=svi_name)
        active_obj = context.active.get(obj)
        if active_obj is None:
            return

        matches = True

        if svi.index != svi_interface['index']:
            matches = False

        # Confirm that it is a bridge.
        # FIXME: Normally, the querier functionality would be disabled for
        # non-multicast SVIs. However, the kernel does not perform ND proxy the
        # same way as ARP proxy.  In particular, for instances on the same
        # supervisor, the kernel will not perform ND proxy. Therefore, these
        # must be allowed to exchange neighbour solicitation and neighbour
        # advertisement messages, which use multicast. See function
        # br_do_suppress_nd() in net/bridge/br_arp_nd_proxy.c.
        expected_bridge_attributes = {
            'IFLA_BR_MCAST_ROUTER':         2,
            'IFLA_BR_MCAST_SNOOPING':       1,
            'IFLA_BR_MCAST_QUERIER':        1,
            'IFLA_BR_MCAST_IGMP_VERSION':   3,
            'IFLA_BR_MCAST_MLD_VERSION':    2,
        }
        link_info = svi_interface.get_attr('IFLA_LINKINFO')
        if link_info is None:
            matches = False
        elif link_info.get_attr('IFLA_INFO_KIND') != 'bridge':
            matches = False
        else:
            # Check bridge attributes are appropriate.
            link_info_data = link_info.get_attr('IFLA_INFO_DATA')
            if link_info_data is not None:
                for attr_name, expected_value in expected_bridge_attributes.items():
                    attr_value = link_info_data.get_attr(attr_name)
                    if attr_value is None:
                        logging.warning("Kernel netlink interface did not report attribute '{}' for interface '{}': unexpected behaviour may occur.".format(attr_name, svi_name))
                    elif attr_value != expected_value:
                        logging.debug("Netlink interface '{}' does not have expected value for attribute '{}'.".format(svi_name, attr_name))
                        matches = False

        # See if master has changed.
        master_index = svi_interface.get_attr('IFLA_MASTER')
        if svi.master != master_index:
            matches = False

        # Forcing re-addition of an SVI to recompute its index, table and
        # master attributes.
        if svi_interface['event'] == 'RTM_NEWLINK':
            if not matches or obj != active_obj:
                logging.debug("Forcing re-addition of netlink SVI '{}'.".format(svi_name))
                svi.index = None
                svi.table = 0
                svi.master = None
                context.active.remove_if_exact(active_obj)
                context.pending_add.add(active_obj)
        elif svi_interface['event'] == 'RTM_DELLINK':
            if matches and obj == active_obj:
                logging.debug("Forcing re-addition of netlink SVI '{}'.".format(svi_name))
                svi.index = None
                svi.table = 0
                svi.master = None
                context.active.remove_must_match(active_obj)
                context.pending_add.add(active_obj)

    @classmethod
    def event_link_vxlan(cls, context: NetlinkEventContext, vxlan_interface: pyroute2.netlink.nlmsg) -> None:
        link_info = vxlan_interface.get_attr('IFLA_LINKINFO')
        if link_info is None or link_info.get_attr('IFLA_INFO_KIND') != 'vxlan':
            return

        vxlan_name = vxlan_interface.get_attr('IFLA_IFNAME')
        vxlan_index = vxlan_interface['index']
        master_index = vxlan_interface.get_attr('IFLA_MASTER')
        if master_index is None or not vxlan_name or not vxlan_index:
            return
        try:
            svi = next(svi for svi in context.svi_map.values() if svi.index == master_index)
        except StopIteration:
            return
        svi_config = context.svi_config.get(svi.name, context.default_svi_config)

        if vxlan_interface['event'] == 'RTM_NEWLINK':
            if vxlan_index not in svi.vxlan:
                svi.vxlan[vxlan_index] = vxlan_name
                context.add(VXLANState(svi=svi.name, index=vxlan_index))
            elif svi.vxlan[vxlan_index] != vxlan_name:
                old_vxlan_name = svi.vxlan[vxlan_index]
                svi.vxlan[vxlan_index] = vxlan_name
                if svi_config.multicast:
                    context.remove(MDBEntryState(svi=svi.name,
                                                 device=old_vxlan_name,
                                                 group=ipaddress.IPv6Address('ff02::16')))
                    context.add(MDBEntryState(svi=svi.name,
                                              device=vxlan_name,
                                              group=ipaddress.IPv6Address('ff02::16')))
        elif vxlan_interface['event'] == 'RTM_DELLINK':
            if vxlan_index in svi.vxlan:
                old_vxlan_name = svi.vxlan.pop(vxlan_index)
                context.remove(VXLANState(svi=svi.name, index=vxlan_index))
                if svi_config.multicast:
                    context.remove(MDBEntryState(svi=svi.name,
                                                 device=old_vxlan_name,
                                                 group=ipaddress.IPv6Address('ff02::16')))

    @classmethod
    def event_set(cls, context: NetlinkEventContext, set: pyroute2.netlink.nlmsg) -> None:
        if set['header']['type'] & 0xFF != nftsocket.NFT_MSG_NEWSET:
            return
        family = str(NFProto(set['nfgen_family'])).lower()
        table_name = set.get_attr('NFTA_SET_NAME')
        set_name = set.get_attr('NFTA_SET_NAME')
        logging.debug("Forcing re-addition of all corresponding netlink set elements because set '{} {} {}' was re-created.".format(family, table_name, set_name))
        while True:
            try:
                obj = context.active.popitem_by_type(cls)
            except KeyError:
                break
            else:
                context.pending_add.add(obj)

    @classmethod
    def event_elements(cls, context: NetlinkEventContext, elements: pyroute2.netlink.nlmsg) -> None:
        family = str(NFProto(elements['nfgen_family'])).lower()
        table_name = elements.get_attr('NFTA_SET_ELEM_LIST_TABLE')
        set_name = elements.get_attr('NFTA_SET_ELEM_LIST_SET')
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
                svi_name, = struct.unpack('@16s', key)
            except struct.error:
                raise NetlinkError("unexpected length of key in set '{}/{}': {}".format(table_name, NFTablesSets.svis, len(key))) from None
            else:
                svi_name = svi_name.rstrip(b'\x00').decode('utf-8')

            obj = cls(name=svi_name)
            active_obj = context.active.get(obj)
            if active_obj is None:
                if elements['header']['type'] & 0xFF == nftsocket.NFT_MSG_NEWSETELEM and not context.pending_add.contains_exact(obj) and not context.pending_remove.contains_need_not_match(obj):
                    logging.debug("Marking netlink set element '{}' in '{} {} {}' for removal because it is not wanted.".format(svi_name, family, table_name, set_name))
                    context.pending_remove.add(obj)
                return

            if elements['header']['type'] & 0xFF == nftsocket.NFT_MSG_NEWSETELEM:
                if obj != active_obj:
                    logging.debug("Forcing re-addition of netlink set element '{}' in '{} {} {}'.".format(svi_name, family, table_name, set_name))
                    context.active.remove_if_exact(active_obj)
                    context.pending_add.add(active_obj)
            elif elements['header']['type'] & 0xFF == nftsocket.NFT_MSG_DELSETELEM:
                if obj == active_obj:
                    logging.debug("Forcing re-addition of netlink set element '{}' in '{} {} {}'.".format(svi_name, family, table_name, set_name))
                    context.active.remove_must_match(active_obj)
                    context.pending_add.add(active_obj)

    @classmethod
    def load(cls, context: NetlinkLoadContext) -> None:
        # Loading the SVIs ensures two things:
        #  a) the SVI internal state (svi_map) is accurate
        #  b) the SVI set contains the desired elements
        for svi in context.svi_map.values():
            svi.index = None
            svi.table = 0
            svi.master = None
            obj = cls(name=svi.name)
            if not context.pending_add.contains_exact(obj):
                # The SVI may have been in the pending_add state and the last reference
                # unregistered, which caused it be removed from the pending_add state,
                # without also adding it to the pending_remove state. Force a removal
                # to delete the svi_map element.
                context.pending_remove.add(obj)
                continue
            try:
                obj.fetch(context)
            except NetlinkError as e:
                logging.error(e.message_sentence)
            except Exception:
                logging.exception("Unexpected exception while fetching SVI data:")

        def handle_netlink_error(iterator: collections.abc.Iterator[T], set_name: str) -> collections.abc.Iterator[T]:
            try:
                yield from iterator
            except pyroute2.NetlinkError as e:
                if e.code == errno.ENOENT:
                    # Ignore non-existent table or set, as it will be created.
                    return
                logging.error("Failed to load SVIs from netfilter set '{}': {} ({}).".format(set_name, os.strerror(e.code), e.code))

        results_bridge = context.nft_raw.get_elements(NFProto.BRIDGE, context.table_name, str(NFTablesSets.svis))
        results_bridge_mcast = context.nft_raw.get_elements(NFProto.BRIDGE, context.table_name, str(NFTablesSets.multicast_svis))
        results_inet = context.nft_raw.get_elements(NFProto.INET, context.table_name, str(NFTablesSets.svis))
        results_combined = itertools.chain(
            zip(itertools.repeat((NFProto.BRIDGE, NFTablesSets.svis)),
                handle_netlink_error(results_bridge, 'bridge {} {}'.format(context.table_name, NFTablesSets.svis))),
            zip(itertools.repeat((NFProto.BRIDGE, NFTablesSets.multicast_svis)),
                handle_netlink_error(results_bridge_mcast, 'bridge {} {}'.format(context.table_name, NFTablesSets.multicast_svis))),
            zip(itertools.repeat((NFProto.INET, NFTablesSets.svis)),
                handle_netlink_error(results_inet, 'inet {} {}'.format(context.table_name, NFTablesSets.svis))),
        )
        set_elements_by_set: dict[tuple[NFProto, NFTablesSets], set[str]] = {}
        for (family, set_name), (key, value) in results_combined:
            try:
                svi_name, = struct.unpack('@16s', key)
            except struct.error:
                raise NetlinkError("unexpected length of key in set '{} {} {}': {}".format(str(family).lower(), context.table_name, set_name, len(key))) from None
            else:
                svi_name = svi_name.rstrip(b'\x00').decode('utf-8')
                set_elements_by_set.setdefault((family, set_name), set()).add(svi_name)

        all_set_elements = set.union(*set_elements_by_set.values()) if set_elements_by_set else set()
        common_set_elements = set.intersection(set_elements_by_set.get((NFProto.BRIDGE, NFTablesSets.svis), set()),
                                               set_elements_by_set.get((NFProto.INET, NFTablesSets.svis), set()))
        mcast_set_elements = set_elements_by_set.get((NFProto.BRIDGE, NFTablesSets.multicast_svis), set())
        for svi_name in all_set_elements:
            obj = cls(name=svi_name)

            try:
                context.pending_add.remove_if_exact(obj)
            except KeyError:
                # The earlier loop would have added the object to the
                # pending_remove state.
                if svi_name not in context.svi_map:
                    logging.debug("Marking netlink SVI '{}' for removal because it is not wanted.".format(obj.name))
                    context.pending_remove.add(obj)
            else:
                try:
                    svi = context.svi_map[obj.name]
                except KeyError:
                    logging.critical("SVI '{}' in pending state, but without internal state (this is a bug).".format(obj.name))
                    context.pending_add.add(obj)
                else:
                    svi_config = context.svi_config.get(svi.name, context.default_svi_config)

                    if svi.index is None or svi.table == 0:
                        logging.debug("Marking netlink SVI '{}' as requiring addition because interface index and/or table aren't computed.".format(obj.name))
                        svi.index = None
                        context.pending_add.add(obj)
                    elif svi.name not in common_set_elements:
                        logging.debug("Marking netlink SVI '{}' as requiring addition because it is not included in all sets.".format(obj.name))
                        context.pending_add.add(obj)
                    elif svi_config.multicast != (svi.name in mcast_set_elements):
                        logging.debug("Marking netlink SVI '{}' as requiring addition because its multicast configuration doesn't match the multicast set.".format(obj.name))
                        context.pending_add.add(obj)
                    else:
                        result = context.ipr.get_links(svi.index)
                        svi_interface = result[0] if len(result) == 1 else None
                        if svi_interface is None:
                            logging.critical("could not find SVI '{}'.".format(svi.name))
                            context.pending_add.add(obj)
                            continue

                        # Check bridge attributes are appropriate (it should already have been confirmed as a bridge).

                        # FIXME: Normally, the querier functionality would
                        # be disabled for non-multicast SVIs. However, the
                        # kernel does not perform ND proxy the same way as
                        # ARP proxy.  In particular, for instances on the
                        # same supervisor, the kernel will not perform ND
                        # proxy. Therefore, these must be allowed to
                        # exchange neighbour solicitation and neighbour
                        # advertisement messages, which use multicast. See
                        # function br_do_suppress_nd() in
                        # net/bridge/br_arp_nd_proxy.c.
                        matches = True
                        expected_bridge_attributes = {
                            'IFLA_BR_MCAST_ROUTER':         2,
                            'IFLA_BR_MCAST_SNOOPING':       1,
                            'IFLA_BR_MCAST_QUERIER':        1,
                            'IFLA_BR_MCAST_IGMP_VERSION':   3,
                            'IFLA_BR_MCAST_MLD_VERSION':    2,
                        }
                        link_info = svi_interface.get_attr('IFLA_LINKINFO')
                        if link_info is not None and link_info.get_attr('IFLA_INFO_KIND') == 'bridge':
                            link_info_data = link_info.get_attr('IFLA_INFO_DATA')
                            if link_info_data is not None:
                                for attr_name, expected_value in expected_bridge_attributes.items():
                                    attr_value = link_info_data.get_attr(attr_name)
                                    if attr_value is None:
                                        logging.warning("Kernel netlink interface did not report attribute '{}' for interface '{}': unexpected behaviour may occur.".format(attr_name, svi_name))
                                    elif attr_value != expected_value:
                                        logging.debug("Netlink interface '{}' does not have expected value for attribute '{}'.".format(svi_name, attr_name))
                                        matches = False
                        if matches:
                            logging.debug("Marking netlink SVI '{}' as active.".format(obj.name))
                            context.active.add(obj)
                        else:
                            logging.debug("Marking netlink SVI '{}' as requiring addition because bridge attributes are inappropriate.".format(obj.name))
                            context.pending_add.add(obj)

    def fetch(self, context: NetlinkLoadContext | NetlinkOperationContext) -> None:
        # This method fetches the netlink state for an SVI and stores
        # the index, table and master attributes.
        try:
            svi = context.svi_map[self.name]
        except KeyError:
            raise NetlinkError("requested data fetch for SVI '{}' which is not registered".format(self.name)) from None

        if svi.index is None:
            result = context.ipr.link_lookup(ifname=svi.name)
            svi_index = result[0] if len(result) == 1 else None
            if svi_index is None:
                raise NetlinkError("could not find SVI '{}'".format(svi.name))

            result = context.ipr.get_links(svi_index)
            svi_interface = result[0] if len(result) == 1 else None
            if svi_interface is None:
                raise NetlinkError("could not find SVI '{}'.".format(svi.name))

            # Confirm that it is a bridge.
            link_info = svi_interface.get_attr('IFLA_LINKINFO')
            if link_info is None:
                raise NetlinkError("could not get SVI '{}' link information".format(svi.name))
            if link_info.get_attr('IFLA_INFO_KIND') != 'bridge':
                raise NetlinkError("SVI '{}' is not a bridge".format(svi.name))

            svi.index = svi_index
            svi.table = context.svi_config.get(svi.name, context.default_svi_config).host_routes_table
            if svi.table == 0:
                # Get table associated with ancestor VRF.
                master_index = svi_interface.get_attr('IFLA_MASTER')
                while master_index is not None:
                    result = context.ipr.get_links(master_index)
                    master_interface = result[0] if len(result) == 1 else None
                    if master_interface is None:
                        raise NetlinkError("failed to get master interface '{}'".format(master_index))
                    link_info = master_interface.get_attr('IFLA_LINKINFO')
                    if link_info.get_attr('IFLA_INFO_KIND') != 'vrf':
                        master_index = master_interface.get_attr('IFLA_MASTER')
                        continue
                    link_info_data = link_info.get_attr('IFLA_INFO_DATA')
                    if link_info_data is None:
                        raise NetlinkError("VRF interface ID '{}' has no link information data".format(master_index))
                    svi.table = link_info_data.get_attr('IFLA_VRF_TABLE')
                    break
                else:
                    svi.table = 254  # main routing table

            svi.master = svi_interface.get_attr('IFLA_MASTER')

            svi_config = context.svi_config.get(self.name, context.default_svi_config)

            # Get VXLAN slave devices.
            old_vxlan_devices = svi.vxlan.copy()
            result = context.ipr.link_lookup(master=svi.index)
            links = context.ipr.get_links(*result) if result else []
            for port_interface in links:
                link_info = port_interface.get_attr('IFLA_LINKINFO')
                if link_info is None:
                    continue
                if link_info.get_attr('IFLA_INFO_KIND') != 'vxlan':
                    continue
                vxlan_name = port_interface.get_attr('IFLA_IFNAME')
                if vxlan_name is None:
                    continue
                vxlan_index = port_interface['index']
                if not vxlan_index:
                    continue
                try:
                    old_vxlan_name = old_vxlan_devices.pop(vxlan_index)
                except KeyError:
                    svi.vxlan[vxlan_index] = vxlan_name
                    context.add(VXLANState(svi=self.name, index=vxlan_index))
                    if svi_config.multicast:
                        context.add(MDBEntryState(svi=self.name,
                                                  device=vxlan_name,
                                                  group=ipaddress.IPv6Address('ff02::16')))
                else:
                    if old_vxlan_name != vxlan_name:
                        svi.vxlan[vxlan_index] = vxlan_name
                        if svi_config.multicast:
                            context.remove(MDBEntryState(svi=self.name,
                                                         device=old_vxlan_name,
                                                         group=ipaddress.IPv6Address('ff02::16')))
                            context.add(MDBEntryState(svi=self.name,
                                                      device=vxlan_name,
                                                      group=ipaddress.IPv6Address('ff02::16')))
            for vxlan_index, vxlan_name in old_vxlan_devices.items():
                del svi.vxlan[vxlan_index]
                context.remove(VXLANState(svi=self.name, index=vxlan_index))
                if svi_config.multicast:
                    context.remove(MDBEntryState(svi=self.name,
                                                 device=vxlan_name,
                                                 group=ipaddress.IPv6Address('ff02::16')))

    def add(self, context: NetlinkOperationContext) -> None:
        try:
            svi = context.svi_map[self.name]
        except KeyError:
            raise NetlinkError("requested addition for SVI '{}' which is not registered".format(self.name)) from None
        svi_config = context.svi_config.get(self.name, context.default_svi_config)

        self.fetch(context)

        if svi.index is not None:
            try:
                # FIXME: Normally, the querier functionality would be disabled
                # for non-multicast SVIs. However, the kernel does not perform
                # ND proxy the same way as ARP proxy.  In particular, for
                # instances on the same supervisor, the kernel will not perform
                # ND proxy. Therefore, these must be allowed to exchange
                # neighbour solicitation and neighbour advertisement messages,
                # which use multicast. See function br_do_suppress_nd() in
                # net/bridge/br_arp_nd_proxy.c.
                context.ipr.link('set', index=svi.index,
                                 IFLA_LINKINFO={'attrs': [
                                     ('IFLA_INFO_KIND', 'bridge'),
                                     ('IFLA_INFO_DATA', {'attrs': [
                                         ('IFLA_BR_MCAST_ROUTER',       2),
                                         ('IFLA_BR_MCAST_SNOOPING',     1),
                                         ('IFLA_BR_MCAST_QUERIER',      1),
                                         ('IFLA_BR_MCAST_IGMP_VERSION', 3),
                                         ('IFLA_BR_MCAST_MLD_VERSION',  2),
                                     ]})
                                 ]})
            except pyroute2.NetlinkError as e:
                raise NetlinkError("failed to set SVI '{}' bridge attributes: {} ({})".format(svi.name, os.strerror(e.code), e.code)) from None

        encoded_name = self.name.encode('utf-8')
        if len(encoded_name) > 15:
            raise NetlinkError("failed to add SVI to set because name exceeds 15 characters: {}".format(self.name))
        key = struct.pack('@16s', encoded_name)
        try:
            context.nft_raw.set_element(NFProto.BRIDGE, context.table_name, str(NFTablesSets.svis), key, create=True, update=True)
            context.nft_raw.set_element(NFProto.INET, context.table_name, str(NFTablesSets.svis), key, create=True, update=True)
        except pyroute2.NetlinkError as e:
            raise NetlinkError("failed to add SVI '{}' element to set 'bridge|inet {} {}': {} ({})".format(self.name, context.table_name, NFTablesSets.svis, os.strerror(e.code), e.code)) from None

        try:
            if svi_config.multicast:
                context.nft_raw.set_element(NFProto.BRIDGE, context.table_name, str(NFTablesSets.multicast_svis), key, create=True, update=True)
            else:
                context.nft_raw.del_element(NFProto.BRIDGE, context.table_name, str(NFTablesSets.multicast_svis), key)
        except pyroute2.NetlinkError as e:
            raise NetlinkError("failed to set SVI '{}' membership in set 'bridge {} {}': {} ({})".format(self.name, context.table_name, NFTablesSets.multicast_svis, os.strerror(e.code), e.code)) from None

        logging.info("Added SVI '{}'.".format(self.name))

    def modify(self, context: NetlinkOperationContext, old: typing.Self) -> None:
        self.add(context)

    def delete(self, context: NetlinkOperationContext) -> None:
        context.svi_map.pop(self.name, None)
        encoded_name = self.name.encode('utf-8')
        if len(encoded_name) > 15:
            raise NetlinkError("failed to remove SVI from set because name exceeds 15 characters: {}".format(self.name))
        key = struct.pack('@16s', encoded_name)
        try:
            context.nft_raw.del_element(NFProto.BRIDGE, context.table_name, str(NFTablesSets.svis), key)
            context.nft_raw.del_element(NFProto.BRIDGE, context.table_name, str(NFTablesSets.multicast_svis), key)
            context.nft_raw.del_element(NFProto.INET, context.table_name, str(NFTablesSets.svis), key)
        except pyroute2.NetlinkError as e:
            raise NetlinkError("failed to delete SVI '{}' from set '{}': {} ({})".format(self.name, NFTablesSets.svis, os.strerror(e.code), e.code)) from None
        else:
            logging.info("Removed SVI '{}'.".format(self.name))
