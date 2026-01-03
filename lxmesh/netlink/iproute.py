__all__ = ['IPRSocketExtended', 'IPRouteExtended']

import ipaddress
import socket
import typing

import pyroute2  # type: ignore[import-untyped]
from pyroute2 import netlink, protocols
from pyroute2.common import hexdump  # type: ignore[import-untyped]
from pyroute2.netlink import nla, nlmsg, rtnl  # type: ignore[import-untyped]
from pyroute2.netlink.rtnl.marshal import MarshalRtnl  # type: ignore[import-untyped]


class mdb_entry_base(nla):  # type: ignore[misc]  # No stubs.
    fields = (('ifindex', 'I'),
              ('state', 'B'),
              ('flags', 'B'),
              ('vid', 'H'),
              ('addr', '16s'),
              ('proto', '>H'),
              ('__pad', '2x'))

    def encode(self) -> None:
        addr = self['addr']
        proto = self['proto']
        if addr:
            if isinstance(addr, str):
                try:
                    addr = ipaddress.ip_address(addr)
                except ValueError:
                    pass
            if isinstance(addr, ipaddress.IPv4Address):
                self['addr'] = addr.packed + (b'\x00' * 12)
                if not proto:
                    self['proto'] = protocols.ETH_P_IP
            elif isinstance(addr, ipaddress.IPv6Address):
                self['addr'] = addr.packed
                if not proto:
                    self['proto'] = protocols.ETH_P_IPV6
            elif isinstance(addr, str):
                self['addr'] = bytes.fromhex(addr.replace(':', '')) + (b'\x00' * 6)
                if proto is None:
                    self['proto'] = 0
        super().encode()

    def decode(self) -> None:
        super().decode()
        if self['addr']:
            match self['proto']:
                case 0:
                    self['addr'] = hexdump(self['addr'][:6])
                case protocols.ETH_P_IP:
                    self['addr'] = ipaddress.IPv4Address(self['addr'][:4])
                case protocols.ETH_P_IPV6:
                    self['addr'] = ipaddress.IPv6Address(self['addr'])


class mdbmsg_base(nlmsg):  # type: ignore[misc]  # No stubs.
    fields = (('family', 'B'),
              ('__pad', '3x'),
              ('ifindex', 'I'))


class mdbmsg(mdbmsg_base):
    __slots__ = ()

    prefix = 'MDBA_'
    nla_map = (('MDBA_UNSPEC', 'none'),
               ('MDBA_MDB', 'mdb'),
               ('MDBA_ROUTER', 'router'))

    class mdb(nla):  # type: ignore[misc]  # No stubs.
        prefix = 'MDBA_'
        nla_map = (('MDBA_MDB_UNSPEC', 'none'),
                   ('MDBA_MDB_ENTRY', 'mdb_entry'))

        class mdb_entry(nla):  # type: ignore[misc]  # No stubs.
            nla_map = (('MDBA_MDB_ENTRY_UNSPEC', 'none'),
                       ('MDBA_MDB_ENTRY_INFO', 'mdb_entry_info'))

            class mdb_entry_info(mdb_entry_base):
                prefix = 'MDBA_MDB_EATTR_'
                nla_map = (('MDBA_MDB_EATTR_UNSPEC', 'none'),
                           ('MDBA_MDB_EATTR_TIMER', 'cdata'),
                           ('MDBA_MDB_EATTR_SRC_LIST', 'cdata'),
                           ('MDBA_MDB_EATTR_GROUP_MODE', 'cdata'),
                           ('MDBA_MDB_EATTR_SOURCE', 'cdata'),
                           ('MDBA_MDB_EATTR_RTPROT', 'uint8'),
                           ('MDBA_MDB_EATTR_DST', 'cdata'),
                           ('MDBA_MDB_EATTR_DST_PORT', 'cdata'),
                           ('MDBA_MDB_EATTR_VNI', 'cdata'),
                           ('MDBA_MDB_EATTR_IFINDEX', 'cdata'),
                           ('MDBA_MDB_EATTR_SRC_VNI', 'cdata'))

    class router(nla):  # type: ignore[misc]  # No stubs.
        pass


class mdbsetmsg(mdbmsg_base):
    __slots__ = ()

    prefix = 'MDBA_SET_'
    nla_map = (('MDBA_SET_ENTRY_UNSPEC', 'none'),
               ('MDBA_SET_ENTRY', 'mdb_entry'),
               ('MDBA_SET_ENTRY_ATTRS', 'set_attrs'))

    class mdb_entry(mdb_entry_base):
        pass

    class set_attrs(nla):  # type: ignore[misc]  # No stubs.
        nla_flags = netlink.NLA_F_NESTED
        prefix = 'MDBE_ATTR_'
        nla_map = (('MDBE_ATTR_UNSPEC', 'none'),
                   ('MDBE_ATTR_SOURCE', 'cdata'),
                   ('MDBE_ATTR_SRC_LIST', 'cdata'),
                   ('MDBE_ATTR_GROUP_MODE', 'cdata'),
                   ('MDBE_ATTR_RTPROT', 'uint8'),
                   ('MDBE_ATTR_DST', 'cdata'),
                   ('MDBE_ATTR_DST_PORT', 'cdata'),
                   ('MDBE_ATTR_VNI', 'cdata'),
                   ('MDBE_ATTR_IFINDEX', 'cdata'),
                   ('MDBE_ATTR_SRC_VNI', 'cdata'))


class MarshalRtnlExtended(MarshalRtnl):  # type: ignore[misc]  # No stubs.
    msg_map = MarshalRtnl.msg_map.copy()
    msg_map[rtnl.RTM_DELMDB] = mdbmsg
    msg_map[rtnl.RTM_GETMDB] = mdbmsg
    msg_map[rtnl.RTM_NEWMDB] = mdbmsg


class IPRSocketExtended(pyroute2.IPRSocket):  # type: ignore[misc]  # No stubs.
    def __init__(self, *args: typing.Any, **kwarg: typing.Any) -> None:
        super().__init__(*args, **kwarg)
        self.marshal = MarshalRtnlExtended()


class IPRouteExtended(pyroute2.IPRoute):  # type: ignore[misc]  # No stubs.
    def __init__(self, *args: typing.Any, **kwarg: typing.Any) -> None:
        nlm_generator = kwarg.pop('nlm_generator', False)
        if nlm_generator:
            raise ValueError("generator mode not supported")
        super().__init__(*args, nlm_generator=False, **kwarg)
        self.marshal = MarshalRtnlExtended()

    def get_mdb(self,
                family: socket.AddressFamily = socket.AF_BRIDGE,
                match: typing.Any = None,
                **kwarg: typing.Any) -> tuple[mdbmsg_base, ...]:
        return self.mdb('dump', family=family, match=match or kwarg)

    def mdb(self,
            command: str | tuple[int, int, type[mdbmsg_base]],
            **kwarg: typing.Any) -> tuple[mdbmsg_base, ...]:
        if (command == 'dump') and ('match' not in kwarg):
            dump_match = kwarg
        else:
            dump_match = kwarg.pop('match', None)

        flags_dump = netlink.NLM_F_REQUEST | netlink.NLM_F_DUMP
        flags_base = netlink.NLM_F_REQUEST | netlink.NLM_F_ACK
        flags_create = flags_base | netlink.NLM_F_CREATE | netlink.NLM_F_EXCL
        flags_append = flags_base | netlink.NLM_F_CREATE
        flags_change = flags_base | netlink.NLM_F_REPLACE
        flags_replace = flags_change | netlink.NLM_F_CREATE

        commands = {'add': (rtnl.RTM_NEWMDB, flags_create, mdbsetmsg),
                    'set': (rtnl.RTM_NEWMDB, flags_replace, mdbsetmsg),
                    'replace': (rtnl.RTM_NEWMDB, flags_replace, mdbsetmsg),
                    'change': (rtnl.RTM_NEWMDB, flags_change, mdbsetmsg),
                    'del': (rtnl.RTM_DELMDB, flags_base, mdbsetmsg),
                    'remove': (rtnl.RTM_DELMDB, flags_base, mdbsetmsg),
                    'delete': (rtnl.RTM_DELMDB, flags_base, mdbsetmsg),
                    'dump': (rtnl.RTM_GETMDB, flags_dump, mdbmsg),
                    'get': (rtnl.RTM_GETMDB, flags_base, mdbmsg),
                    'append': (rtnl.RTM_NEWMDB, flags_append, mdbsetmsg)}

        command_type:   int
        flags:          int
        msgcls:         type[mdbmsg_base]
        (command_type, flags, msgcls) = commands.get(command, command)  # type: ignore[arg-type] # Ugly, but following pyroute2 convention.
        msg = msgcls()
        for field in msg.fields:
            msg[field[0]] = kwarg.pop(field[0], 0)
        msg['family'] = msg['family'] or socket.AF_BRIDGE
        msg['attrs'] = []

        for key in kwarg:
            nla = msgcls.name2nla(key)
            if kwarg[key] is not None:
                msg['attrs'].append([nla, kwarg[key]])

        ret: tuple[mdbmsg_base, ...]
        ret = self.nlm_request(msg,
                               msg_type=command_type,
                               msg_flags=flags)
        if dump_match:
            ret = self._match(dump_match, ret)

        if not (command_type == rtnl.RTM_GETMDB and self.nlm_generator):
            ret = tuple(ret)

        return ret
