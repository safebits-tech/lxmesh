__all__ = ['MDBEntryState']

import errno
import ipaddress
import logging
import os
import socket

import pyroute2  # type: ignore # No stubs.
import pyroute2.netlink  # type: ignore # No stubs.
import pyroute2.netlink.rtnl  # type: ignore # No stubs.

from lxmesh.netlink import constants
from lxmesh.netlink.exceptions import NetlinkError
from lxmesh.netlink.state import NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext, NetlinkSVI
from lxmesh.state import StateObject


class MDBEntryState(StateObject[NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext]):
    svi:    str
    device: str
    group:  ipaddress.IPv4Address | ipaddress.IPv6Address | str

    @classmethod
    def init(cls, context: NetlinkInitialiseContext) -> None:
        context.register_rt_subscription(cls.event_mdb, pyroute2.netlink.rtnl.RTNLGRP_MDB,
                                         family=socket.AF_BRIDGE, event='RTM_NEWMDB')
        context.register_rt_subscription(cls.event_mdb, pyroute2.netlink.rtnl.RTNLGRP_MDB,
                                         family=socket.AF_BRIDGE, event='RTM_DELMDB')

    @classmethod
    def event_mdb(cls, context: NetlinkEventContext, mdb_msg: pyroute2.netlink.nlmsg) -> None:
        try:
            svi = next(svi for svi in context.svi_map.values() if svi.index == mdb_msg['ifindex'])
        except StopIteration:
            if mdb_msg['event'] != 'RTM_NEWMDB':
                return
            svi = NetlinkSVI(refcount=0, name='', index=None)
            return
        mdb = mdb_msg.get_attr('MDBA_MDB')
        if mdb is None:
            return

        for mdb_entry in mdb.get_attrs('MDBA_MDB_ENTRY'):
            for mdb_entry_info in mdb_entry.get_attrs('MDBA_MDB_ENTRY_INFO'):
                proto = mdb_entry_info.get_attr('MDBA_MDB_EATTR_RTPROT')
                if proto != constants.lxmesh.RTPROT_LXMESH:
                    continue
                group = mdb_entry_info['addr']
                if not group:
                    continue
                device_index = mdb_entry_info['ifindex']
                if not device_index:
                    continue
                try:
                    device_name = socket.if_indextoname(device_index)
                except OSError as e:
                    if e.errno != errno.ENXIO:
                        logging.warning("Failed to translate device index '{}' from MDB event: {} ({}).".format(device_index, os.strerror(e.errno), e.errno))
                    continue

                if svi.index is None:
                    obj = cls(svi='@{}'.format(mdb_msg['ifindex']), device='@{}'.format(device_index), group=group)
                    if context.pending_remove.contains_need_not_match(obj):
                        continue
                    logging.debug("Marking netlink MDB entry '{} dev {} port {}' for removal because it is not wanted.".format(group, mdb_msg['ifindex'], device_name))
                    context.pending_remove.add(obj)
                    continue

                obj = cls(svi=svi.name, device=device_name, group=group)
                active_obj = context.active.get(obj)
                if active_obj is None:
                    if mdb_msg['event'] == 'RTM_NEWMDB' and not context.pending_add.contains_exact(obj) and not context.pending_remove.contains_need_not_match(obj):
                        logging.debug("Marking netlink MDB entry '{} dev {} port {}' for removal because it is not wanted.".format(group, svi.name, device_name))
                        context.pending_remove.add(obj)
                    continue

                matches = True
                if mdb_entry_info['state'] != constants.kernel.MDB_PERMANENT:
                    matches = False

                if mdb_msg['event'] == 'RTM_NEWMDB':
                    if not matches or obj != active_obj:
                        # Forcing the MDBEntry to be re-added will effectively replace
                        # any entry that does not match our expectations. If the
                        # currently installed entry is identical, the operation is
                        # effectively a no-op (a RTM_NEWMDB notification may still be
                        # generated, but it will effectively be ignored; no
                        # RTM_DELMDB notification is generated).
                        logging.debug("Forcing re-addition of netlink MDB entry '{} dev {} port {}'.".format(group, svi.name, device_name))
                        context.active.remove_if_exact(active_obj)
                        context.pending_add.add(active_obj)
                elif mdb_msg['event'] == 'RTM_DELMDB':
                    if matches and obj == active_obj:
                        # Only bother re-adding a MDBEntry if the deleted one matches
                        # our expectations. The same considerations as above also
                        # stand.
                        logging.debug("Forcing re-addition of netlink MDB entry '{} dev {} port {}'.".format(group, svi.name, device_name))
                        context.active.remove_must_match(active_obj)
                        context.pending_add.add(active_obj)

    @classmethod
    def load(cls, context: NetlinkLoadContext) -> None:
        try:
            result = context.ipr.get_mdb()
        except pyroute2.NetlinkError as e:
            raise NetlinkError("failed to load MDB entries: {} ({})".format(os.strerror(e.code), e.code))
        for mdb_msg in result:
            if mdb_msg['event'] not in ('RTM_GETMDB', 'RTM_NEWMDB'):
                # FIXME: The events are RTM_GETMDB, at least on kernel 6.2,
                # which is inconsistent with all other subsystems. We also
                # check for RTM_NEWMDB, just in case this gets fixed in the
                # future.
                continue
            try:
                svi = next(svi for svi in context.svi_map.values() if svi.index == mdb_msg['ifindex'])
            except StopIteration:
                continue
            mdb = mdb_msg.get_attr('MDBA_MDB')
            if mdb is None:
                continue

            for mdb_entry in mdb.get_attrs('MDBA_MDB_ENTRY'):
                for mdb_entry_info in mdb_entry.get_attrs('MDBA_MDB_ENTRY_INFO'):
                    proto = mdb_entry_info.get_attr('MDBA_MDB_EATTR_RTPROT')
                    if proto != constants.lxmesh.RTPROT_LXMESH:
                        continue
                    group = mdb_entry_info['addr']
                    if not group:
                        continue
                    device_index = mdb_entry_info['ifindex']
                    if not device_index:
                        continue
                    try:
                        device_name = socket.if_indextoname(device_index)
                    except OSError as e:
                        if e.errno != errno.ENXIO:
                            logging.warning("Failed to translate device index '{}' from MDB event: {} ({}).".format(device_index, os.strerror(e.errno), e.errno))
                        continue

                    obj = cls(svi=svi.name, device=device_name, group=group)
                    try:
                        context.pending_add.remove_if_exact(obj)
                    except KeyError:
                        logging.debug("Marking netlink MDB entry '{} dev {} port {}' for removal because it is not wanted.".format(group, svi.name, device_name))
                        obj = cls(svi='@{}'.format(mdb_msg['ifindex']), device='@{}'.format(device_index), group=group)
                        context.pending_remove.add(obj)
                    else:
                        matches = True
                        if mdb_entry_info['state'] != constants.kernel.MDB_PERMANENT:
                            matches = False

                        if matches:
                            logging.debug("Marking netlink MDB entry '{} dev {} port {}' as active.".format(group, svi.name, device_name))
                            context.active.add(obj)
                        else:
                            logging.debug("Marking netlink MDB entry '{} dev {} port {}' as requiring addition.".format(group, svi.name, device_name))
                            context.pending_add.add(obj)

    def add(self, context: NetlinkOperationContext) -> None:
        try:
            svi_index = context.svi_map[self.svi].index
        except KeyError:
            svi_index = None
        if svi_index is None:
            raise NetlinkError("cannot add MDB entry without knowing interface index of '{}'".format(self.svi)) from None
        try:
            device_index = socket.if_nametoindex(self.device)
        except OSError:
            raise NetlinkError("cannot add MDB entry without knowing interface index of '{}'".format(self.device)) from None
        entry = dict(ifindex=device_index, state=constants.kernel.MDB_PERMANENT, addr=self.group)
        entry_attrs = [('MDBE_ATTR_RTPROT', constants.lxmesh.RTPROT_LXMESH)]
        try:
            context.ipr.mdb('replace', ifindex=svi_index, entry=entry, entry_attrs={'attrs': entry_attrs})
        except pyroute2.NetlinkError as e:
            if e.code == errno.ENODEV:
                return
            raise NetlinkError("failed to add MDB entry '{} dev {} port {}': {} ({})".format(self.group, self.svi, self.device, os.strerror(e.code), e.code)) from None
        else:
            logging.info("Added MDB entry '{} dev {} port {}'.".format(self.group, self.svi, self.device))

    # No modify handler is included, as the add handler depends on the prior
    # addition of Device objects (which adds the port to the bridge SVI).

    def delete(self, context: NetlinkOperationContext) -> None:
        svi_index: int | None
        if self.svi.startswith('@'):
            try:
                svi_index = int(self.svi[1:])
            except ValueError:
                raise NetlinkError("invalid interface indentifier for MDB entry: {}".format(self.svi)) from None
        else:
            try:
                svi_index = context.svi_map[self.svi].index
            except KeyError:
                svi_index = None
            if svi_index is None:
                raise NetlinkError("cannot delete MDB entry without knowing interface index of '{}'".format(self.svi)) from None
        if self.device.startswith('@'):
            try:
                device_index = int(self.device[1:])
            except ValueError:
                raise NetlinkError("invalid interface indentifier for MDB entry: {}".format(self.device)) from None
        else:
            try:
                device_index = socket.if_nametoindex(self.device)
            except OSError:
                return
        entry = dict(ifindex=device_index, addr=self.group)
        try:
            context.ipr.mdb('del', ifindex=svi_index, entry=entry)
        except pyroute2.NetlinkError as e:
            if e.code == errno.ENOENT:
                return
            raise NetlinkError("failed to delete MDB entry '{} dev {} port {}': {} ({})".format(self.group, self.svi, self.device, os.strerror(e.code), e.code)) from None
        else:
            logging.info("Deleted MDB entry '{} dev {} port {}'.".format(self.group, self.svi, self.device))
