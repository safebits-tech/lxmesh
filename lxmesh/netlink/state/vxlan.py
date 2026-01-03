from __future__ import annotations

__all__ = ['VXLANState']

import itertools
import logging
import os
import socket
import typing

import pyroute2  # type: ignore[import-untyped]
import pyroute2.netlink  # type: ignore[import-untyped]
import pyroute2.netlink.rtnl  # type: ignore[import-untyped]

from lxmesh.netlink.exceptions import NetlinkError
from lxmesh.netlink.state import NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext, NetlinkSVI
from lxmesh.state import StateObject


class VXLANState(StateObject[NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext]):
    svi:    str
    index:  int

    @classmethod
    def init(cls, context: NetlinkInitialiseContext) -> None:
        context.register_rt_subscription(cls.event_link, pyroute2.netlink.rtnl.RTNLGRP_LINK,
                                         family=socket.AF_UNSPEC, event='RTM_NEWLINK')

    @classmethod
    def event_link(cls, context: NetlinkEventContext, interface: pyroute2.netlink.nlmsg) -> None:
        if interface['event'] != 'RTM_NEWLINK':
            return

        ifname = interface.get_attr('IFLA_IFNAME')
        if ifname is None:
            ifname = '@{}'.format(interface['index'])
        link_info = interface.get_attr('IFLA_LINKINFO')
        if link_info is None or link_info.get_attr('IFLA_INFO_KIND') != 'vxlan':
            return

        master_index = interface.get_attr('IFLA_MASTER')
        if master_index is not None:
            try:
                svi = next(svi for svi in context.svi_map.values() if svi.index == master_index)
            except StopIteration:
                svi = None
        else:
            svi = None
        if svi is None:
            logging.debug("Ignoring netlink event about VXLAN interface '{}' because we don't care about it.".format(ifname))
            return

        obj = cls(svi=svi.name, index=interface['index'])
        active_obj = context.active.get(obj)
        if active_obj is None:
            return
        slave_kind = link_info.get_attr('IFLA_INFO_SLAVE_KIND')
        slave_data = link_info.get_attr('IFLA_INFO_SLAVE_DATA')
        if slave_kind != 'bridge' or slave_data is None:
            # May no longer be associated to the bridge, not really our problem.
            return

        svi_config = context.svi_config.get(svi.name, context.default_svi_config)

        matches = True

        expected_bridge_port_attributes = {
            'IFLA_BRPORT_LEARNING':         0,
            'IFLA_BRPORT_UNICAST_FLOOD':    0,
            'IFLA_BRPORT_PROXYARP':         0,
            'IFLA_BRPORT_GUARD':            1,
            'IFLA_BRPORT_MULTICAST_ROUTER': 0,
            'IFLA_BRPORT_MCAST_FLOOD':      1 if svi_config.multicast else 0,
            'IFLA_BRPORT_BCAST_FLOOD':      0,
            'IFLA_BRPORT_NEIGH_SUPPRESS':   1,
            'IFLA_BRPORT_ISOLATED':         0,
        }
        for attr_name, expected_value in expected_bridge_port_attributes.items():
            attr_value = slave_data.get_attr(attr_name)
            if attr_value is None:
                logging.warning("Kernel netlink interface did not report attribute '{}' for VXLAN interface '{}': unexpected behaviour may occur.".format(attr_name, ifname))
            elif attr_value != expected_value:
                logging.debug("Netlink interface '{}' does not have expected value for attribute '{}'.".format(ifname, attr_name))
                matches = False

        if not matches or obj != active_obj:
            # Forcing the VXLAN to be "re-added" will effectively modify
            # the link object.
            logging.debug("Forcing re-addition of VXLAN interface '{}'.".format(ifname))
            context.active.remove_if_exact(active_obj)
            context.pending_add.add(active_obj)

    @classmethod
    def load(cls, context: NetlinkLoadContext) -> None:
        port_interfaces: list[tuple[NetlinkSVI, pyroute2.netlink.nlmsg]] = []
        for svi in context.svi_map.values():
            if svi.index is None:
                continue
            try:
                result = context.ipr.link_lookup(master=svi.index)
                links = context.ipr.get_links(*result) if result else []
            except pyroute2.NetlinkError as e:
                logging.error("Failed to load interfaces enslaved to '{}': {} ({}).".format(svi.name, os.strerror(e.code), e.code))
            else:
                port_interfaces.extend(zip(itertools.repeat(svi), links))
        for svi, port_interface in port_interfaces:
            port_name = port_interface.get_attr('IFLA_IFNAME')
            if port_name is None:
                continue

            link_info = port_interface.get_attr('IFLA_LINKINFO')
            if link_info is None or link_info.get_attr('IFLA_INFO_KIND') != 'vxlan':
                continue

            obj = cls(svi=svi.name, index=port_interface['index'])

            try:
                context.pending_add.remove_if_exact(obj)
            except KeyError:
                continue

            slave_kind = link_info.get_attr('IFLA_INFO_SLAVE_KIND')
            slave_data = link_info.get_attr('IFLA_INFO_SLAVE_DATA')
            if slave_kind != 'bridge' or slave_data is None:
                # May no longer be associated to the bridge, not really our problem.
                context.active.add(obj)
                continue

            svi_config = context.svi_config.get(svi.name, context.default_svi_config)

            matches = True

            expected_bridge_port_attributes = {
                'IFLA_BRPORT_LEARNING':         0,
                'IFLA_BRPORT_UNICAST_FLOOD':    0,
                'IFLA_BRPORT_PROXYARP':         0,
                'IFLA_BRPORT_GUARD':            1,
                'IFLA_BRPORT_MULTICAST_ROUTER': 0,
                'IFLA_BRPORT_MCAST_FLOOD':      1 if svi_config.multicast else 0,
                'IFLA_BRPORT_BCAST_FLOOD':      0,
                'IFLA_BRPORT_NEIGH_SUPPRESS':   1,
                'IFLA_BRPORT_ISOLATED':         0,
            }
            for attr_name, expected_value in expected_bridge_port_attributes.items():
                attr_value = slave_data.get_attr(attr_name)
                if attr_value is None:
                    logging.warning("Kernel netlink interface did not report attribute '{}' for interface '{}': unexpected behaviour may occur.".format(attr_name, port_name))
                elif attr_value != expected_value:
                    logging.debug("Netlink interface '{}' does not have expected value for attribute '{}'.".format(port_name, attr_name))
                    matches = False

            if matches:
                logging.debug("Marking netlink VXLAN interface '{}' as active.".format(port_name))
                context.active.add(obj)
            else:
                logging.debug("Marking netlink VXLAN interface '{}' as requiring addition.".format(port_name))
                context.pending_add.add(obj)

    def add(self, context: NetlinkOperationContext) -> None:
        svi_config = context.svi_config.get(self.svi, context.default_svi_config)

        try:
            context.ipr.link('set', index=self.index,
                             IFLA_LINKINFO={'attrs': [
                                 ('IFLA_INFO_SLAVE_KIND', 'bridge'),
                                 ('IFLA_INFO_SLAVE_DATA', {'attrs': [
                                     ('IFLA_BRPORT_LEARNING',         0),
                                     ('IFLA_BRPORT_UNICAST_FLOOD',    0),
                                     ('IFLA_BRPORT_PROXYARP',         0),
                                     ('IFLA_BRPORT_GUARD',            1),
                                     ('IFLA_BRPORT_MULTICAST_ROUTER', 0),
                                     ('IFLA_BRPORT_MCAST_FLOOD',      1 if svi_config.multicast else 0),
                                     ('IFLA_BRPORT_BCAST_FLOOD',      0),
                                     ('IFLA_BRPORT_NEIGH_SUPPRESS',   1),
                                     ('IFLA_BRPORT_ISOLATED',         0),
                                 ]})
                             ]})
        except pyroute2.NetlinkError as e:
            raise NetlinkError("failed to configure VXLAN interface '{}' for SVI '{}': {} ({})".format(self.index, self.svi, os.strerror(e.code), e.code)) from None
        else:
            logging.info("Configured VXLAN interface '{}' for SVI '{}'.".format(self.index, self.svi))

    def modify(self, context: NetlinkOperationContext, old: typing.Self) -> None:
        self.add(context)

    def delete(self, context: NetlinkOperationContext) -> None:
        # There is nothing we need to do here, as we only ensure VXLAN
        # interfaces have a subset of attributes set correctly.
        pass
