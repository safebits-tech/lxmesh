from __future__ import annotations

__all__ = ['RouteState']

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
from lxmesh.netlink.state import NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext, NetlinkSVI
from lxmesh.state import StateObject


class RouteState(StateObject[NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext]):
    svi:    str
    prefix: ipaddress.IPv4Network | ipaddress.IPv6Network

    @classmethod
    def init(cls, context: NetlinkInitialiseContext) -> None:
        context.register_rt_subscription(cls.event_route, pyroute2.netlink.rtnl.RTNLGRP_IPV4_ROUTE,
                                         family=socket.AF_INET, event='RTM_NEWROUTE',
                                         field_filters=dict(proto=constants.lxmesh.RTPROT_LXMESH))
        context.register_rt_subscription(cls.event_route, pyroute2.netlink.rtnl.RTNLGRP_IPV4_ROUTE,
                                         family=socket.AF_INET, event='RTM_DELROUTE',
                                         field_filters=dict(proto=constants.lxmesh.RTPROT_LXMESH))
        context.register_rt_subscription(cls.event_route, pyroute2.netlink.rtnl.RTNLGRP_IPV6_ROUTE,
                                         family=socket.AF_INET6, event='RTM_NEWROUTE',
                                         field_filters=dict(proto=constants.lxmesh.RTPROT_LXMESH))
        context.register_rt_subscription(cls.event_route, pyroute2.netlink.rtnl.RTNLGRP_IPV6_ROUTE,
                                         family=socket.AF_INET6, event='RTM_DELROUTE',
                                         field_filters=dict(proto=constants.lxmesh.RTPROT_LXMESH))

    @classmethod
    def event_route(cls, context: NetlinkEventContext, route: pyroute2.netlink.nlmsg) -> None:
        table = route.get_attr('RTA_TABLE')
        prefix = route.get_attr('RTA_DST')
        if prefix is None:
            return
        prefix = ipaddress.ip_network(ipaddress.ip_address(prefix))
        if route['dst_len'] != prefix.max_prefixlen:
            return
        interface = route.get_attr('RTA_OIF')
        expected_scope = {
            socket.AF_INET:     constants.kernel.RT_SCOPE_LINK,
            socket.AF_INET6:    constants.kernel.RT_SCOPE_UNIVERSE,
        }[route['family']]
        try:
            svi = next(svi for svi in context.svi_map.values() if svi.index == interface)
        except StopIteration:
            # Force deletion of route if it was created.
            svi = NetlinkSVI(refcount=0, name='', table=None)
        if svi.table == 0:
            # We do not know which table we want the host routes in.
            return
        elif svi.table is None or table != svi.table:
            if route['event'] != 'RTM_NEWROUTE':
                return
            obj = cls(svi='@{}'.format(table), prefix=prefix)
            if context.pending_remove.contains_need_not_match(obj):
                return
            logging.debug("Netlink route '{}' in table '{}' should not have been installed.".format(prefix, table))
            context.pending_remove.add(obj)
            return

        obj = cls(svi=svi.name, prefix=prefix)
        active_obj = context.active.get(obj)
        if active_obj is None:
            if route['event'] == 'RTM_NEWROUTE' and not context.pending_add.contains_exact(obj) and not context.pending_remove.contains_need_not_match(obj):
                logging.debug("Marking netlink route '{}' in table '{}' for removal because it is not wanted.".format(prefix, table))
                context.pending_remove.add(obj)
            return

        matches = True
        if route['type'] != constants.kernel.RTN_UNICAST:
            logging.debug("Netlink route '{}' in table '{}' is not of type unicast.".format(prefix, table))
            matches = False
        elif route['scope'] != expected_scope:
            logging.debug("Netlink route '{}' in table '{}' does not have the expected scope.".format(prefix, table))
            matches = False

        if route['event'] == 'RTM_NEWROUTE':
            if not matches or obj != active_obj:
                # Forcing the Route to be re-added will effectively replace any
                # entry that does not match our expectations. If the currently
                # installed entry is identical, the operation is effectively a
                # no-op (a RTM_NEWROUTE notification may still be generated, but
                # it will effectively be ignored; no RTM_DELROUTE notification
                # is generated).
                logging.debug("Forcing re-addition of netlink route '{}' in table '{}'.".format(prefix, table))
                context.active.remove_if_exact(active_obj)
                context.pending_add.add(active_obj)
        elif route['event'] == 'RTM_DELROUTE':
            if matches and obj == active_obj:
                # Only bother re-adding a Route if the deleted one matches our
                # expectations. The same considerations as above also stand.
                logging.debug("Forcing re-addition of netlink route '{}' in table '{}'.".format(prefix, table))
                context.active.remove_must_match(active_obj)
                context.pending_add.add(active_obj)

    @classmethod
    def load(cls, context: NetlinkLoadContext) -> None:
        try:
            result_ip4 = context.ipr.get_routes(family=socket.AF_INET,
                                                proto=constants.lxmesh.RTPROT_LXMESH)
            result_ip6 = context.ipr.get_routes(family=socket.AF_INET6,
                                                proto=constants.lxmesh.RTPROT_LXMESH)
        except pyroute2.NetlinkError as e:
            raise NetlinkError("failed to load routes: {} ({})".format(os.strerror(e.code), e.code)) from None
        for route in itertools.chain(result_ip4, result_ip6):
            if route['event'] != 'RTM_NEWROUTE':
                continue
            table = route.get_attr('RTA_TABLE')
            prefix = route.get_attr('RTA_DST')
            if prefix is None:
                continue
            prefix = ipaddress.ip_network(ipaddress.ip_address(prefix))
            if route['dst_len'] != prefix.max_prefixlen:
                continue
            interface = route.get_attr('RTA_OIF')
            try:
                svi = next(svi for svi in context.svi_map.values() if svi.index == interface)
            except StopIteration:
                # Force deletion of route.
                svi = NetlinkSVI(refcount=0, name='', table=None)
            if svi.table == 0:
                # We do not know which table we want the host routes in.
                continue
            elif svi.table is None or table != svi.table:
                logging.debug("Netlink route '{}' in table '{}' should not have been installed.".format(prefix, table))
                obj = cls(svi='@{}'.format(table), prefix=prefix)
                context.pending_remove.add(obj)
                continue

            obj = cls(svi=svi.name, prefix=prefix)
            try:
                context.pending_add.remove_if_exact(obj)
            except KeyError:
                logging.debug("Marking netlink route '{}' in table '{}' for removal because it is not wanted.".format(prefix, table))
                context.pending_remove.add(obj)
            else:
                matches = True
                expected_scope = {
                    socket.AF_INET:     constants.kernel.RT_SCOPE_LINK,
                    socket.AF_INET6:    constants.kernel.RT_SCOPE_UNIVERSE,
                }[route['family']]
                if route['type'] != constants.kernel.RTN_UNICAST:
                    logging.debug("Netlink route '{}' in table '{}' is not of type unicast.".format(prefix, table))
                    matches = False
                elif route['scope'] != expected_scope:
                    logging.debug("Netlink route '{}' in table '{}' does not have the expected scope.".format(prefix, table))
                    matches = False

                if matches:
                    logging.debug("Marking netlink route '{}' in table '{}' as active.".format(prefix, table))
                    context.active.add(obj)
                else:
                    logging.debug("Marking netlink route '{}' in table '{}' as requiring addition.".format(prefix, table))
                    context.pending_add.add(obj)

    def add(self, context: NetlinkOperationContext) -> None:
        try:
            svi = context.svi_map[self.svi]
        except KeyError:
            raise NetlinkError("cannot add route for unknown SVI '{}'".format(self.svi)) from None
        if svi.table is None:
            return
        if svi.index is None or svi.table == 0:
            raise NetlinkError("cannot add route without knowing SVI '{}' index and destination table".format(self.svi))
        try:
            kw = {}
            if svi.table < 256:
                kw['table'] = svi.table
            else:
                kw['table'] = constants.kernel.RT_TABLE_UNSPEC
                kw['RTA_TABLE'] = svi.table
            if self.prefix.version == 4:
                kw['family'] = socket.AF_INET
                kw['scope'] = constants.kernel.RT_SCOPE_LINK
            elif self.prefix.version == 6:
                kw['family'] = socket.AF_INET6
                kw['scope'] = constants.kernel.RT_SCOPE_UNIVERSE
            context.ipr.route('replace', dst=str(self.prefix), oif=svi.index,
                              proto=constants.lxmesh.RTPROT_LXMESH, type=constants.kernel.RTN_UNICAST, **kw)
        except pyroute2.NetlinkError as e:
            raise NetlinkError("failed to add route '{}' to table '{}': {} ({})".format(self.prefix, svi.table, os.strerror(e.code), e.code)) from None
        else:
            logging.info("Added route '{} dev {}' to table '{}'.".format(self.prefix, self.svi, svi.table))

    # FIXME: annotate 'old' with typing.Self in Python 3.11+.
    def modify(self, context: NetlinkOperationContext, old: RouteState) -> None:
        self.add(context)

    def delete(self, context: NetlinkOperationContext) -> None:
        if self.svi.startswith('@'):
            try:
                table = int(self.svi[1:])
            except ValueError:
                raise NetlinkError("invalid table identifier for route: {}".format(self.svi)) from None
        else:
            try:
                svi = context.svi_map[self.svi]
            except KeyError:
                raise NetlinkError("cannot delete route for unknown SVI '{}'".format(self.svi)) from None
            if svi.table is None or svi.table == 0:
                raise NetlinkError("cannot delete route without knowing SVI '{}' destination table".format(self.svi))
            table = svi.table
        try:
            kw = {}
            if table < 256:
                kw['table'] = table
            else:
                kw['table'] = constants.kernel.RT_TABLE_UNSPEC
                kw['RTA_TABLE'] = table
            if self.prefix.version == 4:
                kw['scope'] = constants.kernel.RT_SCOPE_NOWHERE
                kw['family'] = socket.AF_INET
            elif self.prefix.version == 6:
                kw['family'] = socket.AF_INET6
            context.ipr.route('del', dst=str(self.prefix), proto=constants.lxmesh.RTPROT_LXMESH, type=constants.kernel.RTN_UNICAST, **kw)
        except pyroute2.NetlinkError as e:
            if e.code == errno.ESRCH:
                # Route doesn't exist anymore.
                return
            raise NetlinkError("failed to delete route '{}' from table '{}': {} ({})".format(self.prefix, table, os.strerror(e.code), e.code)) from None
        else:
            logging.info("Deleted route '{} dev {}' from table '{}'.".format(self.prefix, self.svi, table))
