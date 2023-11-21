from __future__ import annotations

__all__ = ['NeighbourState']

import errno
import ipaddress
import itertools
import logging
import os
import socket

import pyroute2  # type: ignore # No stubs.
import pyroute2.netlink  # type: ignore # No stubs.
import pyroute2.netlink.rtnl  # type: ignore # No stubs.

from lxmesh.netlink import constants
from lxmesh.netlink.exceptions import NetlinkError
from lxmesh.netlink.state import NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext
from lxmesh.state import StateObject


class NeighbourState(StateObject[NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext]):
    svi:        str
    address:    ipaddress.IPv4Address | ipaddress.IPv6Address
    lladdr:     str = StateObject.field(key=False)

    @classmethod
    def init(cls, context: NetlinkInitialiseContext) -> None:
        context.register_rt_subscription(cls.event_neigh, pyroute2.netlink.rtnl.RTNLGRP_NEIGH,
                                         family=socket.AF_INET, event='RTM_NEWNEIGH',
                                         attribute_filters=dict(NDA_PROTOCOL=constants.lxmesh.RTPROT_LXMESH))
        context.register_rt_subscription(cls.event_neigh, pyroute2.netlink.rtnl.RTNLGRP_NEIGH,
                                         family=socket.AF_INET, event='RTM_DELNEIGH',
                                         attribute_filters=dict(NDA_PROTOCOL=constants.lxmesh.RTPROT_LXMESH))
        context.register_rt_subscription(cls.event_neigh, pyroute2.netlink.rtnl.RTNLGRP_NEIGH,
                                         family=socket.AF_INET6, event='RTM_NEWNEIGH',
                                         attribute_filters=dict(NDA_PROTOCOL=constants.lxmesh.RTPROT_LXMESH))
        context.register_rt_subscription(cls.event_neigh, pyroute2.netlink.rtnl.RTNLGRP_NEIGH,
                                         family=socket.AF_INET6, event='RTM_DELNEIGH',
                                         attribute_filters=dict(NDA_PROTOCOL=constants.lxmesh.RTPROT_LXMESH))

    @classmethod
    def event_neigh(cls, context: NetlinkEventContext, neighbour: pyroute2.netlink.nlmsg) -> None:
        if neighbour['ifindex'] is None:
            return
        address: ipaddress.IPv4Address | ipaddress.IPv6Address | None
        address = neighbour.get_attr('NDA_DST')
        if address is None:
            return
        address = ipaddress.ip_address(address)
        lladdr = neighbour.get_attr('NDA_LLADDR')
        if lladdr is None:
            return
        try:
            svi = next(svi for svi in context.svi_map.values() if svi.index == neighbour['ifindex'])
        except StopIteration:
            if neighbour['event'] != 'RTM_NEWNEIGH':
                return
            obj = cls(svi='@{}'.format(neighbour['ifindex']), address=address, lladdr=lladdr)
            if context.pending_remove.contains_need_not_match(obj):
                return
            logging.debug("Marking netlink neighbour '{} lladdr {}' on interface '{}' for removal because it is not wanted.".format(address, lladdr, neighbour['ifindex']))
            context.pending_remove.add(obj)
            return

        obj = cls(svi=svi.name, address=address, lladdr=lladdr)
        active_obj = context.active.get(obj)
        if active_obj is None:
            if neighbour['event'] == 'RTM_NEWNEIGH' and not context.pending_add.contains_exact(obj) and not context.pending_remove.contains_need_not_match(obj):
                logging.debug("Marking netlink neighbour '{} lladdr {}' on SVI '{}' for removal because it is not wanted.".format(address, lladdr, svi.name))
                context.pending_remove.add(obj)
            return

        matches = True
        if neighbour['ndm_type'] != constants.kernel.RTN_UNICAST:
            logging.debug("Netlink neighbour '{} lladdr {}' is not of type unicast.".format(address, lladdr))
            matches = False
        elif neighbour['state'] & ~(constants.kernel.NUD_REACHABLE | constants.kernel.NUD_PERMANENT) != 0:
            logging.debug("Netlink neighbour '{} lladdr {}' does not have expected state (0x{:02X}).".format(address, lladdr, neighbour['state']))
            matches = False
        elif neighbour['state'] & (constants.kernel.NUD_REACHABLE | constants.kernel.NUD_PERMANENT) == 0:
            logging.debug("Netlink neighbour '{} lladdr {}' does not have expected state (0x{:02X}).".format(address, lladdr, neighbour['state']))
            matches = False
        elif neighbour['flags'] & constants.kernel.NTF_SELF != 0:
            logging.debug("Netlink neighbour '{} lladdr {}' does not have expected flags (0x{:02X}).".format(address, lladdr, neighbour['flags']))
            matches = False
        elif address.version == 4 and neighbour['flags'] & constants.kernel.NTF_EXT_LEARNED == 0:
            logging.debug("Netlink neighbour '{} lladdr {}' does not have expected flags (0x{:02X}).".format(address, lladdr, neighbour['flags']))
            matches = False
        elif address.version == 6 and neighbour['flags'] & constants.kernel.NTF_EXT_LEARNED != 0:
            logging.debug("Netlink neighbour '{} lladdr {}' does not have expected flags (0x{:02X}).".format(address, lladdr, neighbour['flags']))
            matches = False

        if neighbour['event'] == 'RTM_NEWNEIGH':
            if not matches or obj != active_obj:
                # Forcing the Neighbour to be re-added will effectively replace
                # any entry that does not match our expectations. If the
                # currently installed entry is identical, the operation is
                # effectively a no-op (a RTM_NEWNEIGH notification may still be
                # generated, but it will effectively be ignored; no
                # RTM_DELNEIGH notification is generated).
                logging.debug("Forcing re-addition of netlink neighbour '{} lladdr {}' on SVI '{}'.".format(address, lladdr, svi.name))
                context.active.remove_if_exact(active_obj)
                context.pending_add.add(active_obj)
        elif neighbour['event'] == 'RTM_DELNEIGH':
            if matches and obj == active_obj:
                # Only bother re-adding a Neighbour if the deleted one matches
                # our expectations. The same considerations as above also
                # stand.
                logging.debug("Forcing re-addition of netlink neighbour '{} lladdr {}' on SVI '{}'.".format(address, lladdr, svi.name))
                context.active.remove_must_match(active_obj)
                context.pending_add.add(active_obj)

    @classmethod
    def load(cls, context: NetlinkLoadContext) -> None:
        try:
            result_ip4 = context.ipr.get_neighbours(family=socket.AF_INET,
                                                    protocol=constants.lxmesh.RTPROT_LXMESH)
            result_ip6 = context.ipr.get_neighbours(family=socket.AF_INET6,
                                                    protocol=constants.lxmesh.RTPROT_LXMESH)
        except pyroute2.NetlinkError as e:
            raise NetlinkError("failed to load neighbours: {} ({})".format(os.strerror(e.code), e.code)) from None
        for neighbour in itertools.chain(result_ip4, result_ip6):
            if neighbour['event'] != 'RTM_NEWNEIGH':
                continue
            address: ipaddress.IPv4Address | ipaddress.IPv6Address | None
            address = neighbour.get_attr('NDA_DST')
            if address is None:
                continue
            address = ipaddress.ip_address(address)
            lladdr = neighbour.get_attr('NDA_LLADDR')
            if lladdr is None:
                continue
            if neighbour['ifindex'] is None:
                continue
            try:
                svi = next(svi for svi in context.svi_map.values() if svi.index == neighbour['ifindex'])
            except StopIteration:
                obj = cls(svi='@{}'.format(neighbour['ifindex']), address=address, lladdr=lladdr)
                context.pending_remove.add(obj)
                continue

            obj = cls(svi=svi.name, address=address, lladdr=lladdr)
            try:
                context.pending_add.remove_if_exact(obj)
            except KeyError:
                logging.debug("Marking netlink neighbour '{} lladdr {}' on SVI '{}' for removal because it is not wanted.".format(address, lladdr, svi.name))
                context.pending_remove.add(obj)
            else:
                matches = True
                if neighbour['ndm_type'] != constants.kernel.RTN_UNICAST:
                    logging.debug("Netlink neighbour '{} lladdr {}' on SVI '{}' is not of type unicast.".format(address, lladdr, svi.name))
                    matches = False
                elif neighbour['state'] & ~(constants.kernel.NUD_REACHABLE | constants.kernel.NUD_PERMANENT) != 0:
                    logging.debug("Netlink neighbour '{} lladdr {}' on SVI '{}' does not have expected state (0x{:02X}).".format(address, lladdr, svi.name, neighbour['state']))
                    matches = False
                elif neighbour['state'] & (constants.kernel.NUD_REACHABLE | constants.kernel.NUD_PERMANENT) == 0:
                    logging.debug("Netlink neighbour '{} lladdr {}' on SVI '{}' does not have expected state (0x{:02X}).".format(address, lladdr, svi.name, neighbour['state']))
                    matches = False
                elif neighbour['flags'] & constants.kernel.NTF_SELF != 0:
                    logging.debug("Netlink neighbour '{} lladdr {}' on SVI '{}' does not have expected flags (0x{:02X}).".format(address, lladdr, svi.name, neighbour['flags']))
                    matches = False
                elif address.version == 4 and neighbour['flags'] & constants.kernel.NTF_EXT_LEARNED == 0:
                    logging.debug("Netlink neighbour '{} lladdr {}' on SVI '{}' does not have expected flags (0x{:02X}).".format(address, lladdr, svi.name, neighbour['flags']))
                    matches = False
                elif address.version == 6 and neighbour['flags'] & constants.kernel.NTF_EXT_LEARNED != 0:
                    logging.debug("Netlink neighbour '{} lladdr {}' does not have expected flags (0x{:02X}).".format(address, lladdr, neighbour['flags']))
                    matches = False

                if matches:
                    logging.debug("Marking netlink neighbour '{} lladdr {}' on SVI '{}' as active.".format(address, lladdr, svi.name))
                    context.active.add(obj)
                else:
                    logging.debug("Marking netlink neighbour '{} lladdr {}' on SVI '{}' as requiring addition.".format(address, lladdr, svi.name))
                    context.pending_add.add(obj)

    def add(self, context: NetlinkOperationContext) -> None:
        try:
            svi_index = context.svi_map[self.svi].index
        except KeyError:
            svi_index = None
        if svi_index is None:
            raise NetlinkError("cannot add neighbour without knowing SVI '{}' index".format(self.svi))
        try:
            family = {
                4:  socket.AF_INET,
                6:  socket.AF_INET6,
            }[self.address.version]
            flags = {
                4:  constants.kernel.NTF_EXT_LEARNED,
                6:  0,
            }[self.address.version]
            context.ipr.neigh('replace', family=family, ifindex=svi_index, dst=str(self.address), lladdr=self.lladdr,
                              ndm_type=constants.kernel.RTN_UNICAST, state=constants.kernel.NUD_PERMANENT,
                              flags=flags, protocol=constants.lxmesh.RTPROT_LXMESH)
        except pyroute2.NetlinkError as e:
            raise NetlinkError("failed to add neighbour for '{}' with address '{}' on SVI '{}': {} ({})".format(self.address, self.lladdr, self.svi, os.strerror(e.code), e.code)) from None
        else:
            logging.info("Added neighbour '{}' with address '{}' on SVI '{}'.".format(self.address, self.lladdr, self.svi))

    # FIXME: annotate 'old' with typing.Self in Python 3.11+.
    def modify(self, context: NetlinkOperationContext, old: NeighbourState) -> None:
        self.add(context)

    def delete(self, context: NetlinkOperationContext) -> None:
        svi_index: int | None
        if self.svi.startswith('@'):
            try:
                svi_index = int(self.svi[1:])
            except ValueError:
                raise NetlinkError("invalid interface indentifier for neighbour: {}".format(self.svi)) from None
        else:
            try:
                svi_index = context.svi_map[self.svi].index
            except KeyError:
                svi_index = None
            if svi_index is None:
                raise NetlinkError("cannot delete neighbour without knowing SVI '{}' index".format(self.svi))
        try:
            family = {
                4:  socket.AF_INET,
                6:  socket.AF_INET6,
            }[self.address.version]
            context.ipr.neigh('del', family=family, ifindex=svi_index, dst=str(self.address), lladdr=self.lladdr)
        except pyroute2.NetlinkError as e:
            if e.code == errno.ENOENT:
                return
            raise NetlinkError("failed to delete neighbour for '{}' with address '{}' on SVI '{}': {} ({})".format(self.address, self.lladdr, self.svi, os.strerror(e.code), e.code))
        else:
            logging.info("Deleted neighbour '{}' with address '{}' on SVI '{}'.".format(self.address, self.lladdr, self.svi))
