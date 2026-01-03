from __future__ import annotations

__all__ = ['DeviceState']

import errno
import itertools
import logging
import os
import socket
import typing

import pyroute2  # type: ignore[import-untyped]
import pyroute2.netlink  # type: ignore[import-untyped]
import pyroute2.netlink.rtnl  # type: ignore[import-untyped]

from lxmesh.netlink import constants
from lxmesh.netlink.exceptions import NetlinkError
from lxmesh.netlink.state import NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext, NetlinkSVI
from lxmesh.state import StateObject


class DeviceState(StateObject[NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext]):
    name:   str
    svi:    str | None = StateObject.field(key=False)

    @classmethod
    def init(cls, context: NetlinkInitialiseContext) -> None:
        context.register_rt_subscription(cls.event_link, pyroute2.netlink.rtnl.RTNLGRP_LINK,
                                         family=socket.AF_UNSPEC, event='RTM_NEWLINK')
        # There's no point in subscribing to RTM_DELLINK notifications, since
        # this state object only associates the interface to the SVI bridge,
        # something which doesn't make sense for an interface that doesn't
        # exist anymore.

    @classmethod
    def event_link(cls, context: NetlinkEventContext, port_interface: pyroute2.netlink.nlmsg) -> None:
        if port_interface['event'] != 'RTM_NEWLINK':
            return

        # We only care about veth interfaces that have a name (is there such a
        # thing as an interface without a name?!).
        port_name = port_interface.get_attr('IFLA_IFNAME')
        if port_name is None:
            return
        link_info = port_interface.get_attr('IFLA_LINKINFO')
        if link_info is None or link_info.get_attr('IFLA_INFO_KIND') != 'veth':
            return

        # There are four possible scenarios for RTM_NEWLINK:
        #  1. An interface we're interested in gets its attributes modified, in
        #     which case we want to set it back.
        #  2. An interface with a name we're interested in is created, or an
        #     existing inteface gets renamed to a name we're interested in; in
        #     this case we want to set it up.
        #  3. An interface with a name we're interested in gets renamed to a
        #     name we're not interested in. In this case we want to
        #     disassociate the interface from the SVI bridge.
        #  4. A combination of 2. and 3.: an interface with a name we're
        #     interested in gets renamed to a name we're also interested in. In
        #     this case, the attributes are probably already OK and no further
        #     action is needed; if they aren't, scenario 2 above applies
        #     anyway.

        # Interface modifications cannot be made atomically, which means that
        # RT_NEWLINK events are generated for intermediary states. Without
        # special processing, these would be picked up here as incorrect states
        # and trigger a 're-add', which will in turn generate new RT_NEWLINK
        # events for intermediary states, causing an infinite loop. In lieu of
        # user-definable attributes, we use the interface group to mark such
        # intermediary states. A random one is generated at startup, but
        # unfortunately we are limited to 31 bits of entropy.  However, if an
        # interface is left in an intermediary state by a previous instance of
        # this application that happened to generate the same intermediary
        # group identifier, this would either be picked up when the interfaces
        # are loaded or would simply be ignored by the Device 'ADD' handler,
        # which would configure the interface anyway.
        inter_group = (int.from_bytes(context.instance_id[:4], byteorder='big') & 0x7FFFFFFF) or 1
        if port_interface.get_attr('IFLA_GROUP') == inter_group:
            return

        master_index = port_interface.get_attr('IFLA_MASTER')
        if master_index is not None:
            try:
                svi = next(svi for svi in context.svi_map.values() if svi.index == master_index)
            except StopIteration:
                svi = None
        else:
            svi = None

        obj = cls(name=port_name, svi=svi.name if svi is not None else None)
        active_obj = context.active.get(obj)
        if active_obj is not None:
            matches = True

            addrgenmode = None
            af_spec = port_interface.get_attr('IFLA_AF_SPEC')
            if af_spec is not None:
                af_inet6 = af_spec.get_attr('AF_INET6')
                if af_inet6 is not None:
                    addrgenmode = af_inet6.get_attr('IFLA_INET6_ADDR_GEN_MODE')
            if addrgenmode != constants.kernel.IN6_ADDR_GEN_MODE_NONE:
                logging.debug("Netlink interface '{}' does not have expected IPv6 Address generation mode.".format(port_name))
                matches = False

            expected_bridge_port_attributes = {
                'IFLA_BRPORT_LEARNING':         0,
                'IFLA_BRPORT_UNICAST_FLOOD':    0,
                'IFLA_BRPORT_PROXYARP':         1,
                'IFLA_BRPORT_GUARD':            1,
                'IFLA_BRPORT_MULTICAST_ROUTER': 0,
                'IFLA_BRPORT_MCAST_FLOOD':      0,
                'IFLA_BRPORT_BCAST_FLOOD':      0,
                'IFLA_BRPORT_NEIGH_SUPPRESS':   0,
                'IFLA_BRPORT_ISOLATED':         0,
            }
            slave_kind = link_info.get_attr('IFLA_INFO_SLAVE_KIND')
            slave_data = link_info.get_attr('IFLA_INFO_SLAVE_DATA')
            if slave_kind == 'bridge' and slave_data is not None:
                for attr_name, expected_value in expected_bridge_port_attributes.items():
                    attr_value = slave_data.get_attr(attr_name)
                    if attr_value is None:
                        logging.warning("Kernel netlink interface did not report attribute '{}' for interface '{}': unexpected behaviour may occur.".format(attr_name, port_name))
                    elif attr_value != expected_value:
                        logging.debug("Netlink interface '{}' does not have expected value for attribute '{}'.".format(port_name, attr_name))
                        matches = False
            else:
                matches = False

            if not matches or obj != active_obj:
                # Forcing the Device to be "re-added" will effectively modify
                # the link object. We never delete link objects, so RTM_DELLINK
                # notifications are never generated based on our actions.
                logging.debug("Forcing re-addition of netlink interface '{}'.".format(port_name))
                context.active.remove_if_exact(active_obj)
                context.pending_add.add(active_obj)
        elif context.pending_add.contains_need_not_match(obj):
            # This interface will be set up at the next commit.
            logging.debug("Ignoring netlink event about interface '{}' because we are planning on adding it anyway.".format(port_name))
        elif context.pending_remove.contains_need_not_match(obj):
            # This interface will be disassociated from the SVI bridge at the
            # next commit.
            logging.debug("Ignoring netlink event about interface '{}' because we are planning on removing it anyway.".format(port_name))
        elif obj.svi is not None:
            # This interface is (or was at one point, when this event was
            # generated) associated to an SVI bridge we manage. We're
            # definitely not interested in it (the key (name) is missing from
            # active, pending_add and pending_remove), so mark it for removal
            # quicker.
            logging.debug("Marking netlink interface '{}' for removal because it is associated to the bridge.".format(port_name))
            context.pending_remove.add(obj)
        else:
            logging.debug("Ignoring netlink event about interface '{}' because we don't care about it.".format(port_name))

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
            if link_info is None or link_info.get_attr('IFLA_INFO_KIND') != 'veth':
                continue

            obj = cls(name=port_name, svi=svi.name)

            try:
                context.pending_add.remove_if_exact(obj)
            except KeyError:
                logging.debug("Marking netlink interface '{}' for removal because it is not wanted.".format(port_name))
                context.pending_remove.add(obj)
            else:
                matches = True

                addrgenmode = None
                af_spec = port_interface.get_attr('IFLA_AF_SPEC')
                if af_spec is not None:
                    af_inet6 = af_spec.get_attr('AF_INET6')
                    if af_inet6 is not None:
                        addrgenmode = af_inet6.get_attr('IFLA_INET6_ADDR_GEN_MODE')
                if addrgenmode != constants.kernel.IN6_ADDR_GEN_MODE_NONE:
                    logging.debug("Netlink interface '{}' does not have expected IPv6 Address generation mode.".format(port_name))
                    matches = False

                expected_bridge_port_attributes = {
                    'IFLA_BRPORT_LEARNING':         0,
                    'IFLA_BRPORT_UNICAST_FLOOD':    0,
                    'IFLA_BRPORT_PROXYARP':         1,
                    'IFLA_BRPORT_GUARD':            1,
                    'IFLA_BRPORT_MULTICAST_ROUTER': 0,
                    'IFLA_BRPORT_MCAST_FLOOD':      0,
                    'IFLA_BRPORT_BCAST_FLOOD':      0,
                    'IFLA_BRPORT_NEIGH_SUPPRESS':   0,
                    'IFLA_BRPORT_ISOLATED':         0,
                }
                slave_data = link_info.get_attr('IFLA_INFO_SLAVE_DATA')
                if slave_data is not None:
                    for attr_name, expected_value in expected_bridge_port_attributes.items():
                        attr_value = slave_data.get_attr(attr_name)
                        if attr_value is None:
                            logging.warning("Kernel netlink interface did not report attribute '{}' for interface '{}': unexpected behaviour may occur.".format(attr_name, port_name))
                        elif attr_value != expected_value:
                            logging.debug("Netlink interface '{}' does not have expected value for attribute '{}'.".format(port_name, attr_name))
                            matches = False
                else:
                    matches = False

                inter_group = (int.from_bytes(context.instance_id[:4], byteorder='big') & 0x7FFFFFFF) or 1
                if port_interface.get_attr('IFLA_GROUP') == inter_group:
                    logging.warning("Netlink interface '{}' seems to have been left partially configured.".format(port_name))
                    matches = False

                if matches:
                    logging.debug("Marking netlink interface '{}' as active.".format(port_name))
                    context.active.add(obj)
                else:
                    logging.debug("Marking netlink interface '{}' as requiring addition.".format(port_name))
                    context.pending_add.add(obj)

    def add(self, context: NetlinkOperationContext) -> None:
        if self.svi is None:
            raise NetlinkError("cannot set up interface object '{}' without SVI".format(self.name))
        try:
            svi_index = context.svi_map[self.svi].index
        except KeyError:
            svi_index = None
        if svi_index is None:
            raise NetlinkError("cannot set up interface object without knowing SVI index of '{}'".format(self.svi))
        try:
            ifindex = socket.if_nametoindex(self.name)
        except OSError:
            raise NetlinkError("cannot find interface with name '{}'".format(self.name)) from None
        inter_group = (int.from_bytes(context.instance_id[:4], byteorder='big') & 0x7FFFFFFF) or 1
        try:
            context.ipr.link('set', index=ifindex, state='down',
                             group=inter_group)
            context.ipr.link('set', index=ifindex, master=svi_index,
                             IFLA_AF_SPEC={'attrs': [
                                 ('AF_INET6', {'attrs': [
                                     ('IFLA_INET6_ADDR_GEN_MODE', constants.kernel.IN6_ADDR_GEN_MODE_NONE),
                                 ]})
                             ]})
            context.ipr.link('set', index=ifindex,
                             IFLA_LINKINFO={'attrs': [
                                 ('IFLA_INFO_SLAVE_KIND', 'bridge'),
                                 ('IFLA_INFO_SLAVE_DATA', {'attrs': [
                                     ('IFLA_BRPORT_LEARNING',         0),
                                     ('IFLA_BRPORT_UNICAST_FLOOD',    0),
                                     ('IFLA_BRPORT_PROXYARP',         1),
                                     ('IFLA_BRPORT_GUARD',            1),
                                     ('IFLA_BRPORT_MULTICAST_ROUTER', 0),
                                     ('IFLA_BRPORT_MCAST_FLOOD',      0),
                                     ('IFLA_BRPORT_BCAST_FLOOD',      0),
                                     ('IFLA_BRPORT_NEIGH_SUPPRESS',   0),
                                     ('IFLA_BRPORT_ISOLATED',         0),
                                 ]})
                             ]})
            context.ipr.link('set', index=ifindex, state='up', group=0)
        except pyroute2.NetlinkError as e:
            raise NetlinkError("failed to associate interface '{}' to SVI '{}': {} ({})".format(self.name, self.svi, os.strerror(e.code), e.code)) from None
        else:
            logging.info("Associated interface '{}' to SVI '{}'.".format(self.name, self.svi))

    def modify(self, context: NetlinkOperationContext, old: typing.Self) -> None:
        self.add(context)

    def delete(self, context: NetlinkOperationContext) -> None:
        try:
            ifindex = socket.if_nametoindex(self.name)
        except OSError:
            # May no longer exist
            return
        try:
            context.ipr.link('set', index=ifindex, master=0)
        except pyroute2.NetlinkError as e:
            if e.code == errno.ENODEV:
                # Interface doesn't exist anymore.
                return
            raise NetlinkError("failed to disassociate interface '{}' from SVI '{}': {} ({})".format(self.name, self.svi, os.strerror(e.code), e.code)) from None
        else:
            logging.info("Disassociated interface '{}' from SVI '{}'.".format(self.name, self.svi))
