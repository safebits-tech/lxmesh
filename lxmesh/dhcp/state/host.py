from __future__ import annotations

__all__ = ['HostState']

import ipaddress
import logging
import typing

from lxmesh.dhcp.state import DHCPEventContext, DHCPInitialiseContext, DHCPLoadContext, DHCPOperationContext
from lxmesh.state import StateObject


class HostState(StateObject[DHCPEventContext, DHCPInitialiseContext, DHCPLoadContext, DHCPOperationContext]):
    svi:            str
    device_address: str
    name:           str | None                      = StateObject.field(key=False)
    ip4_address:    ipaddress.IPv4Address | None    = StateObject.field(key=False)
    ip6_address:    ipaddress.IPv6Address | None    = StateObject.field(key=False)

    @classmethod
    def init(cls, context: DHCPInitialiseContext) -> None:
        pass

    @classmethod
    def load(cls, context: DHCPLoadContext) -> None:
        # With a flat-file database, a commit overwrites the entire data, so
        # there's no point in keeping track of what is stored.
        pass

    def add(self, context: DHCPOperationContext) -> None:
        if context.hosts_file is None:
            return
        logging.debug("Adding DHCP entry '{!r}' to hosts file.".format(self))
        context.hosts_file.write('{}'.format(self.device_address))
        if self.name is not None:
            context.hosts_file.write(',{}'.format(self.name))
        if self.ip4_address is not None:
            context.hosts_file.write(',{}'.format(self.ip4_address))
        if self.ip6_address is not None:
            context.hosts_file.write(',[{}]'.format(self.ip6_address))
        context.hosts_file.write('\n')

    def modify(self, context: DHCPOperationContext, old: typing.Self) -> None:
        self.add(context)

    def delete(self, context: DHCPOperationContext) -> None:
        # DHCP hosts are simply not included in the flat-file database, so
        # absolutely nothing to do here.
        pass
