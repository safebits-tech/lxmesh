__all__ = ['FDBEntryState']

import errno
import logging
import os
import socket

import pyroute2  # type: ignore[import-untyped]
import pyroute2.netlink  # type: ignore[import-untyped]
import pyroute2.netlink.rtnl  # type: ignore[import-untyped]

from lxmesh.netlink import constants
from lxmesh.netlink.exceptions import NetlinkError
from lxmesh.netlink.state import NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext
from lxmesh.state import StateObject


class FDBEntryState(StateObject[NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext]):
    lladdr: str
    device: str = StateObject.field(key=False)

    @classmethod
    def init(cls, context: NetlinkInitialiseContext) -> None:
        # FIXME: should be able to filter by protocol, at some point.
        context.register_rt_subscription(cls.event_neigh, pyroute2.netlink.rtnl.RTNLGRP_NEIGH,
                                         family=socket.AF_BRIDGE, event='RTM_NEWNEIGH',
                                         attribute_filters=dict(NDA_VLAN=None))
        context.register_rt_subscription(cls.event_neigh, pyroute2.netlink.rtnl.RTNLGRP_NEIGH,
                                         family=socket.AF_BRIDGE, event='RTM_DELNEIGH',
                                         attribute_filters=dict(NDA_VLAN=None))

    @classmethod
    def event_neigh(cls, context: NetlinkEventContext, fdb_entry: pyroute2.netlink.nlmsg) -> None:
        svi_index = fdb_entry.get_attr('NDA_MASTER')
        if svi_index is None:
            return
        try:
            next(svi for svi in context.svi_map.values() if svi.index == svi_index)
        except StopIteration:
            return
        lladdr = fdb_entry.get_attr('NDA_LLADDR')
        if lladdr is None:
            return
        try:
            device = socket.if_indextoname(fdb_entry['ifindex'])
        except OSError as e:
            if e.errno == errno.ENXIO:
                # Could be an old notification and the device no longer exists.
                return
            raise

        obj = cls(lladdr=lladdr, device=device)
        active_obj = context.active.get(obj)
        if active_obj is None:
            return

        matches = True
        if fdb_entry['state'] & ~(constants.kernel.NUD_REACHABLE | constants.kernel.NUD_NOARP) != 0:
            logging.debug("Netlink FDB entry '{} dev {}' does not have expected state (0x{:02X}).".format(lladdr, device, fdb_entry['state']))
            matches = False
        elif fdb_entry['state'] & (constants.kernel.NUD_REACHABLE | constants.kernel.NUD_NOARP) == 0:
            logging.debug("Netlink FDB entry '{} dev {}' does not have expected state (0x{:02X}).".format(lladdr, device, fdb_entry['state']))
            matches = False
        elif fdb_entry['flags'] & ~(constants.kernel.NTF_MASTER | constants.kernel.NTF_EXT_LEARNED) != 0:
            logging.debug("Netlink FDB entry '{} dev {}' does not have expected flags (0x{:02X}).".format(lladdr, device, fdb_entry['flags']))
            matches = False
        elif fdb_entry['flags'] & constants.kernel.NTF_EXT_LEARNED == 0:
            logging.debug("Netlink FDB entry '{} dev {}' does not have expected flags (0x{:02X}).".format(lladdr, device, fdb_entry['flags']))
            matches = False

        if fdb_entry['event'] == 'RTM_NEWNEIGH':
            if not matches or obj != active_obj:
                # Forcing the FDBEntry to be re-added will effectively replace
                # any entry that does not match our expectations. If the
                # currently installed entry is identical, the operation is
                # effectively a no-op (a RTM_NEWNEIGH notification may still be
                # generated, but it will effectively be ignored; no
                # RTM_DELNEIGH notification is generated).
                logging.debug("Forcing re-addition of netlink FDB entry '{} dev {}'.".format(lladdr, device))
                context.active.remove_if_exact(active_obj)
                context.pending_add.add(active_obj)
        elif fdb_entry['event'] == 'RTM_DELNEIGH':
            if matches and obj == active_obj:
                # Only bother re-adding a FDBEntry if the deleted one matches
                # our expectations. The same considerations as above also
                # stand.
                logging.debug("Forcing re-addition of netlink FDB entry '{} dev {}'.".format(lladdr, device))
                context.active.remove_must_match(active_obj)
                context.pending_add.add(active_obj)

    @classmethod
    def load(cls, context: NetlinkLoadContext) -> None:
        # FIXME: should be able to filter by protocol, at some point.
        fdb_entries = []
        for svi in context.svi_map.values():
            if svi.index is None:
                continue
            try:
                result = context.ipr.get_neighbours(family=socket.AF_BRIDGE, nda_master=svi.index)
            except pyroute2.NetlinkError as e:
                logging.error("Failed to load FDB entries for bridge '{}': {} ({}).".format(svi.name, os.strerror(e.code), e.code))
            else:
                fdb_entries.extend(result)
        for fdb_entry in fdb_entries:
            if fdb_entry['event'] != 'RTM_NEWNEIGH':
                continue
            if fdb_entry['state'] & ~(constants.kernel.NUD_REACHABLE | constants.kernel.NUD_NOARP) != 0:
                continue
            if fdb_entry['state'] & (constants.kernel.NUD_REACHABLE | constants.kernel.NUD_NOARP) == 0:
                continue
            if fdb_entry['flags'] & constants.kernel.NTF_SELF != 0:
                continue
            if fdb_entry['flags'] & constants.kernel.NTF_EXT_LEARNED == 0:
                continue
            if fdb_entry.get_attr('NDA_VLAN') is not None:
                continue
            lladdr = fdb_entry.get_attr('NDA_LLADDR')
            if lladdr is None:
                continue
            try:
                device = socket.if_indextoname(fdb_entry['ifindex'])
            except OSError as e:
                # The device may no longer exist
                if e.errno != errno.ENXIO:
                    logging.error("Failed to translate interface index '{}' to a name: {} ({}).".format(fdb_entry['ifindex'], os.strerror(e.errno), e.errno))
                continue
            obj = cls(lladdr=lladdr, device=device)
            try:
                context.pending_add.remove_if_exact(obj)
            except KeyError:
                result = context.ipr.get_links(fdb_entry['ifindex'])
                port_interface = result[0] if result else None
                if port_interface is None:
                    logging.warning("Failed to lookup device of FDB entry '{} dev {}'.".format(lladdr, device))
                    continue
                link_info = port_interface.get_attr('IFLA_LINKINFO')
                if link_info is None or link_info.get_attr('IFLA_INFO_KIND') != 'veth':
                    logging.debug("Ignoring netlink FDB entry '{} dev {}' because it is not associated to a 'veth' interface.".format(lladdr, device))
                    continue
                logging.debug("Marking netlink FDB entry '{} dev {}' for removal because it is not wanted.".format(lladdr, device))
                obj = cls(lladdr=lladdr, device='@{}'.format(fdb_entry['ifindex']))
                context.pending_remove.add(obj)
            else:
                logging.debug("Marking netlink FDB entry '{} dev {}' as active.".format(lladdr, device))
                context.active.add(obj)

    def add(self, context: NetlinkOperationContext) -> None:
        try:
            ifindex = socket.if_nametoindex(self.device)
        except OSError:
            raise NetlinkError("cannot add FDB entry without knowing interface index of '{}'".format(self.device)) from None
        try:
            context.ipr.fdb('replace', ifindex=ifindex, lladdr=self.lladdr,
                            state=constants.kernel.NUD_NOARP, flags=constants.kernel.NTF_MASTER | constants.kernel.NTF_EXT_LEARNED,
                            protocol=constants.lxmesh.RTPROT_LXMESH)
        except pyroute2.NetlinkError as e:
            if e.code == errno.ENODEV:
                return
            raise NetlinkError("failed to add FDB entry for '{}' on interface '{}': {} ({})".format(self.lladdr, self.device, os.strerror(e.code), e.code)) from None
        else:
            logging.info("Added FDB entry '{} dev {}'.".format(self.lladdr, self.device))

    # No modify handler is included, as the add handler depends on the prior
    # addition of Device objects (which adds the port to the bridge SVI).

    def delete(self, context: NetlinkOperationContext) -> None:
        if self.device.startswith('@'):
            try:
                ifindex = int(self.device[1:])
            except ValueError:
                raise NetlinkError("invalid interface indentifier for FDB entry: {}".format(self.device)) from None
        else:
            try:
                ifindex = socket.if_nametoindex(self.device)
            except OSError:
                return
        try:
            context.ipr.fdb('del', ifindex=ifindex, lladdr=self.lladdr)
        except pyroute2.NetlinkError as e:
            if e.code == errno.ENOENT:
                return
            raise NetlinkError("failed to delete FDB entry for '{}' on interface '{}': {} ({})".format(self.lladdr, self.device, os.strerror(e.code), e.code)) from None
        else:
            logging.info("Deleted FDB entry '{} dev {}'.".format(self.lladdr, self.device))
