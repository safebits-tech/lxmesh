from __future__ import annotations

__all__ = ['SVIState']

import ipaddress
import logging
import socket
import typing

import pyroute2  # type: ignore[import-untyped]
import pyroute2.netlink  # type: ignore[import-untyped]
import pyroute2.netlink.rtnl  # type: ignore[import-untyped]

from lxmesh.dhcp.exceptions import DHCPError
from lxmesh.dhcp.state import DHCPEventContext, DHCPInitialiseContext, DHCPLoadContext, DHCPOperationContext
from lxmesh.state import StateObject


class SVIState(StateObject[DHCPEventContext, DHCPInitialiseContext, DHCPLoadContext, DHCPOperationContext]):
    name:   str

    @classmethod
    def init(cls, context: DHCPInitialiseContext) -> None:
        context.register_rt_subscription(cls.event_link, pyroute2.netlink.rtnl.RTNLGRP_LINK,
                                         family=socket.AF_UNSPEC, event='RTM_NEWLINK')
        context.register_rt_subscription(cls.event_link, pyroute2.netlink.rtnl.RTNLGRP_LINK,
                                         family=socket.AF_UNSPEC, event='RTM_DELLINK')
        context.register_rt_subscription(cls.event_addr, pyroute2.netlink.rtnl.RTNLGRP_LINK,
                                         family=socket.AF_UNSPEC, event='RTM_NEWADDR')
        context.register_rt_subscription(cls.event_addr, pyroute2.netlink.rtnl.RTNLGRP_LINK,
                                         family=socket.AF_UNSPEC, event='RTM_DELADDR')

    @classmethod
    def event_link(cls, context: DHCPEventContext, svi_interface: pyroute2.netlink.nlmsg) -> None:
        # We only care about SVIs that have a name (is there such a thing as an
        # interface without a name?!).
        svi_name = svi_interface.get_attr('IFLA_IFNAME')
        if svi_name is None:
            return

        try:
            svi = context.svi_map[svi_name]
        except KeyError:
            return

        obj = cls(name=svi.name)
        active_obj = context.active.get(obj)
        if active_obj is None:
            return

        matches = True

        if svi.index != svi_interface['index']:
            matches = False
        if svi.mtu != svi_interface.get_attr('IFLA_MTU'):
            matches = False

        # Confirm that it is a bridge.
        link_info = svi_interface.get_attr('IFLA_LINKINFO')
        if link_info is None:
            matches = False
        elif link_info.get_attr('IFLA_INFO_KIND') != 'bridge':
            matches = False

        # Forcing re-addition of an SVI to recompute its index and networks
        # attributes.
        if svi_interface['event'] == 'RTM_NEWLINK':
            if not matches or obj != active_obj:
                logging.debug("Forcing re-addition of DHCP SVI '{}'.".format(svi.name))
                svi.index = None
                svi.mtu = None
                svi.networks = None
                context.active.remove_if_exact(active_obj)
                context.pending_add.add(active_obj)
        elif svi_interface['event'] == 'RTM_DELLINK':
            if matches and obj == active_obj:
                logging.debug("Forcing re-addition of DHCP SVI '{}'.".format(svi.name))
                svi.index = None
                svi.mtu = None
                svi.networks = None
                context.active.remove_must_match(active_obj)
                context.pending_add.add(active_obj)

    @classmethod
    def event_addr(cls, context: DHCPEventContext, ip_config: pyroute2.netlink.nlmsg) -> None:
        try:
            svi = next(svi for svi in context.svi_map.values() if svi.index == ip_config['index'])
        except StopIteration:
            return
        if svi.networks is None:
            return

        obj = cls(name=svi.name)
        active_obj = context.active.get(obj)
        if active_obj is None:
            return

        address = ip_config.get_attr('IFA_ADDRESS')
        if address is None:
            return
        try:
            address = ipaddress.ip_address(address)
        except ValueError:
            logging.warning("Invalid address '{}' on SVI '{}'.".format(address, svi.name))
            return
        if address.is_link_local:
            return
        if ip_config['prefixlen'] > address.max_prefixlen:
            logging.warning("Invalid prefix length for address '{}/{}' on SVI '{}'.".format(address, ip_config['prefixlen'], svi.name))
            return
        network = ipaddress.ip_network(address).supernet(address.max_prefixlen - ip_config['prefixlen'])

        # Forcing re-addition of an SVI to recompute its network attribute.
        if ip_config['event'] == 'RTM_NEWADDR':
            if network not in svi.networks:
                svi.networks = None
                context.active.remove_if_exact(active_obj)
                context.pending_add.add(active_obj)
        elif ip_config['event'] == 'RTM_DELADDR':
            if network in svi.networks:
                svi.networks = None
                context.active.remove_if_exact(active_obj)
                context.pending_add.add(active_obj)

    @classmethod
    def load(cls, context: DHCPLoadContext) -> None:
        for svi in context.svi_map.values():
            svi.index, old_index = None, svi.index
            svi.networks, old_networks = None, svi.networks

            obj = cls(name=svi.name)
            if context.pending_add.contains_exact(obj) or context.active.contains_exact(obj):
                try:
                    obj.fetch(context)
                except DHCPError as e:
                    logging.error("Failed to load DHCP interface '{}': {}.".format(svi.name, e))
                else:
                    if context.active.contains_exact(obj):
                        if svi.index != old_index or svi.networks != old_networks:
                            context.active.remove_if_exact(obj)
                            context.pending_add.add(obj)
            else:
                # An earlier unregister of the SVI which decremented the
                # refcount to 0 may have found the SVI in the pending_add
                # state, causing it to be removed from there. Force a removal
                # in order to delete the internal state from svi_map.
                context.pending_remove.add(obj)

            # With a flat-file database, a commit overwrites the entire data, so
            # there's no point in keeping track of what is stored.

    def fetch(self, context: DHCPLoadContext | DHCPOperationContext) -> None:
        # This method fetches the netlink state for an SVI and stores
        # the index and networks attributes.
        try:
            svi = context.svi_map[self.name]
        except KeyError:
            raise DHCPError("requested fetch of SVI '{}' which is not registered".format(self.name)) from None

        if svi.index is None:
            result = context.ipr.link_lookup(ifname=svi.name)
            svi.index = result[0] if len(result) == 1 else None
            if svi.index is None:
                raise DHCPError("could not find SVI '{}'".format(svi.name))

            result = context.ipr.get_links(svi.index)
            svi_interface = result[0] if len(result) == 1 else None
            if svi_interface is None:
                svi.index = None
                raise DHCPError("could not find SVI '{}'".format(svi.name))

            # Confirm that it is a bridge.
            link_info = svi_interface.get_attr('IFLA_LINKINFO')
            if link_info is None:
                svi.index = None
                raise DHCPError("could not get SVI '{}' link information".format(svi.name))
            if link_info.get_attr('IFLA_INFO_KIND') != 'bridge':
                svi.index = None
                raise DHCPError("SVI '{}' is not a bridge".format(svi.name))

            svi.mtu = svi_interface.get_attr('IFLA_MTU')

        if svi.networks is None:
            # Get IP configuration
            svi.networks = []
            ip_config_list = context.ipr.get_addr(index=svi.index)
            for ip_config in ip_config_list:
                if ip_config['event'] != 'RTM_NEWADDR':
                    continue
                address = ip_config.get_attr('IFA_ADDRESS')
                if address is None:
                    continue
                try:
                    address = ipaddress.ip_address(address)
                except ValueError:
                    logging.warning("Invalid address '{}' on SVI '{}'.".format(address, svi.name))
                    continue
                if address.is_link_local:
                    continue
                if ip_config['prefixlen'] > address.max_prefixlen:
                    logging.warning("Invalid prefix length for address '{}/{}' on SVI '{}'.".format(address, ip_config['prefixlen'], svi.name))
                    continue
                network = ipaddress.ip_network(address).supernet(address.max_prefixlen - ip_config['prefixlen'])
                svi.networks.append(network)

    def add(self, context: DHCPOperationContext) -> None:
        self.fetch(context)

        if context.config_file is None:
            return
        try:
            svi = context.svi_map[self.name]
        except KeyError:
            raise DHCPError("requested fetch of SVI '{}' which is not registered".format(self.name)) from None

        logging.debug("Adding DHCP interface '{}' to configuration file.".format(svi.name))
        context.config_file.write('interface={}\n'.format(svi.name))
        if svi.mtu is None:
            logging.warning("Could not determine MTU of SVI '{}'.".format(svi.name))
        else:
            context.config_file.write('dhcp-option=tag:{},option:mtu,{}\n'.format(svi.name, svi.mtu))
        if svi.networks is None:
            logging.error("Failed to load IP addresses associated to SVI '{}'.".format(svi.name))
        elif not svi.networks:
            logging.warning("SVI '{}' does not have any non-link-local addresses configured.".format(svi.name))
        else:
            for network in svi.networks:
                logging.debug("Adding DHCP range for network '{}' to configuration file.".format(network.network_address))
                if network.version == 4:
                    context.config_file.write('dhcp-range={},static,{}\n'.format(network.network_address, context.ip4_lease_time))
                elif network.version == 6:
                    context.config_file.write('dhcp-range={},static,{},{}\n'.format(network.network_address, network.prefixlen, context.ip6_lease_time))

    def modify(self, context: DHCPOperationContext, old: typing.Self) -> None:
        self.add(context)

    def delete(self, context: DHCPOperationContext) -> None:
        # We do not modify SVIs, so just forget we care about it.
        del context.svi_map[self.name]
