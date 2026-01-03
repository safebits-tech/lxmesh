__all__ = ['NFProto', 'NFTablesRaw']

import binascii
import collections.abc
import enum
import struct
import typing

import pyroute2  # type: ignore[import-untyped]
import pyroute2.netlink  # type: ignore[import-untyped]
from pyroute2.netlink.nfnetlink import nftsocket  # type: ignore[import-untyped]


class NFProto(enum.IntEnum):
    UNSPEC  = 0
    INET    = 1
    IP      = 2
    ARP     = 3
    NETDEV  = 5
    BRIDGE  = 7
    IP6     = 10

    def __str__(self) -> str:
        return self.name


class NFTablesRaw(pyroute2.NFTSocket):  # type: ignore[misc]  # No stubs.
    def __init__(self) -> None:
        super().__init__(nfgen_family=NFProto.UNSPEC)

    @staticmethod
    def parse_comment(userdata: str) -> str:
        userdata_bin = binascii.a2b_hex(''.join(userdata.split(':')))
        type, length = struct.unpack('@BB', userdata_bin[:2])
        if type != 0:
            raise ValueError("unknown user data type '{}'".format(type))
        try:
            if userdata_bin[2 + length - 1] != 0:
                raise ValueError("user data comment is not nul-terminated")
        except IndexError:
            raise ValueError("invalid user data length: expected '{}' and found '{}'".format(length + 2, len(userdata_bin)))
        return userdata_bin[2:2 + length - 1].decode('ascii')

    @staticmethod
    def build_comment(comment: str) -> bytes:
        encoded_comment = comment.encode('ascii') + b'\x00'
        if len(encoded_comment) > 255:
            raise ValueError("comment is too long")
        return struct.pack('@BB', 0, len(encoded_comment)) + encoded_comment

    def get_tables(self,
                   family: NFProto = NFProto.UNSPEC) -> collections.abc.Iterator[tuple[NFProto, str, str | None]]:
        self._nfgen_family = family
        try:
            results = self.request_get(nftsocket.nfgen_msg(), nftsocket.NFT_MSG_GETTABLE)
        finally:
            self._nfgen_family = NFProto.UNSPEC
        for result in results:
            name = result.get_attr('NFTA_TABLE_NAME')
            if name is None:
                continue
            userdata = result.get_attr('NFTA_TABLE_USERDATA')
            if userdata is not None:
                try:
                    comment = self.parse_comment(userdata)
                except ValueError:
                    comment = None
            else:
                comment = None
            yield NFProto(result['nfgen_family']), name, comment

    def add_table(self,
                  family: NFProto,
                  table_name: str,
                  comment: str | None = None,
                  *,
                  replace: bool = False) -> None:
        comment_bin = self.build_comment(comment) if comment is not None else None

        self._nfgen_family = family
        try:
            self.begin()

            if replace:
                # FIXME: kernel 6.3 supports NFT_MSG_DESTROYTABLE
                msg = nftsocket.nft_table_msg()
                msg['attrs'] = [('NFTA_TABLE_NAME', table_name),
                                ('NFTA_TABLE_USERDATA', b'\x42\x00')]
                self.request_put(msg, nftsocket.NFT_MSG_NEWTABLE, pyroute2.netlink.NLM_F_REQUEST | pyroute2.netlink.NLM_F_CREATE)
                msg = nftsocket.nft_table_msg()
                msg['attrs'] = [('NFTA_TABLE_NAME', table_name)]
                self.request_put(msg, nftsocket.NFT_MSG_DELTABLE, pyroute2.netlink.NLM_F_REQUEST)

            msg = nftsocket.nft_table_msg()
            msg['attrs'] = [('NFTA_TABLE_NAME', table_name)]
            if comment_bin is not None:
                msg['attrs'].append(('NFTA_TABLE_USERDATA', comment_bin))
            self.request_put(msg, nftsocket.NFT_MSG_NEWTABLE, pyroute2.netlink.NLM_F_REQUEST | pyroute2.netlink.NLM_F_CREATE | pyroute2.netlink.NLM_F_EXCL)

            self.commit()
        finally:
            self._nfgen_family = NFProto.UNSPEC

    def del_table(self,
                  family: NFProto,
                  table_name: str) -> None:
        msg = nftsocket.nft_table_msg()
        msg['attrs'] = [('NFTA_TABLE_NAME', table_name)]
        self._nfgen_family = family
        try:
            self.request_put(msg, nftsocket.NFT_MSG_DELTABLE, pyroute2.netlink.NLM_F_REQUEST)
        finally:
            self._nfgen_family = NFProto.UNSPEC

    def get_elements(self,
                     family: NFProto,
                     table_name: str,
                     set_name: str) -> collections.abc.Iterator[tuple[bytes, bytes | None]]:
        modifier = pyroute2.netlink.nlmsg_atoms.ip6addr()
        modifier.header = None
        msg = nftsocket.nft_set_elem_list_msg()
        msg['attrs'] = [
            ('NFTA_SET_ELEM_LIST_TABLE', table_name),
            ('NFTA_SET_ELEM_LIST_SET', set_name),
        ]
        self._nfgen_family = family
        try:
            results = self.request_get(msg, nftsocket.NFT_MSG_GETSETELEM)
        finally:
            self._nfgen_family = NFProto.UNSPEC
        for result in results:
            elements = result.get_attr('NFTA_SET_ELEM_LIST_ELEMENTS')
            if elements is None:
                continue
            for element in elements:
                key_attr = element.get_attr('NFTA_SET_ELEM_KEY')
                if key_attr is None:
                    continue
                key = key_attr.get_attr('NFTA_DATA_VALUE')
                if key is None:
                    continue
                value_attr = element.get_attr('NFTA_SET_ELEM_DATA')
                if value_attr is not None:
                    value = value_attr.get_attr('NFTA_DATA_VALUE')
                    yield key, value
                else:
                    yield key, None

    def set_element(self,
                    family: NFProto,
                    table_name: str,
                    set_name: str,
                    key: bytes,
                    value: bytes | None = None,
                    *,
                    create: bool = True,
                    update: bool = True) -> None:
        if not create and not update:
            raise ValueError("cannot set element if creating nor updating is allowed")

        element_attributes: list[tuple[str, typing.Any]] = []
        element_attributes.append(('NFTA_SET_ELEM_KEY', {'attrs': [
            ('NFTA_DATA_VALUE', key),
        ]}))
        if value is not None:
            element_attributes.append(('NFTA_SET_ELEM_DATA', {'attrs': [
                ('NFTA_DATA_VALUE', value),
            ]}))

        # FIXME: This is a hack. Fix once problem is understood.

        self._nfgen_family = family
        try:
            if create:
                self.begin()
                msg = nftsocket.nft_set_elem_list_msg()
                msg['attrs'] = [
                    ('NFTA_SET_ELEM_LIST_TABLE', table_name),
                    ('NFTA_SET_ELEM_LIST_SET', set_name),
                    ('NFTA_SET_ELEM_LIST_ELEMENTS', [{'attrs': element_attributes}]),
                ]
                self.request_put(msg, nftsocket.NFT_MSG_NEWSETELEM, pyroute2.netlink.NLM_F_REQUEST | pyroute2.netlink.NLM_F_CREATE | (pyroute2.netlink.NLM_F_EXCL if not update else 0))
                self.commit()

            if update and value is not None:
                self.begin()
                msg = nftsocket.nft_set_elem_list_msg()
                msg['attrs'] = [
                    ('NFTA_SET_ELEM_LIST_TABLE', table_name),
                    ('NFTA_SET_ELEM_LIST_SET', set_name),
                    ('NFTA_SET_ELEM_LIST_ELEMENTS', [{'attrs': element_attributes}]),
                ]
                self.request_put(msg, nftsocket.NFT_MSG_DELSETELEM, pyroute2.netlink.NLM_F_REQUEST)

                msg = nftsocket.nft_set_elem_list_msg()
                msg['attrs'] = [
                    ('NFTA_SET_ELEM_LIST_TABLE', table_name),
                    ('NFTA_SET_ELEM_LIST_SET', set_name),
                    ('NFTA_SET_ELEM_LIST_ELEMENTS', [{'attrs': element_attributes}]),
                ]
                self.request_put(msg, nftsocket.NFT_MSG_NEWSETELEM, pyroute2.netlink.NLM_F_REQUEST | pyroute2.netlink.NLM_F_CREATE | pyroute2.netlink.NLM_F_REPLACE)
                self.commit()
        finally:
            self._nfgen_family = NFProto.UNSPEC

    def del_element(self,
                    family: NFProto,
                    table_name: str,
                    set_name: str,
                    key: bytes) -> None:
        element_attributes: list[tuple[str, typing.Any]] = []
        element_attributes.append(('NFTA_SET_ELEM_KEY', {'attrs': [
            ('NFTA_DATA_VALUE', key),
        ]}))

        msg = nftsocket.nft_set_elem_list_msg()
        msg['attrs'] = [
            ('NFTA_SET_ELEM_LIST_TABLE', table_name),
            ('NFTA_SET_ELEM_LIST_SET', set_name),
            ('NFTA_SET_ELEM_LIST_ELEMENTS', [{'attrs': element_attributes}]),
        ]
        self._nfgen_family = family
        try:
            self.request_put(msg, nftsocket.NFT_MSG_DELSETELEM, pyroute2.netlink.NLM_F_REQUEST)
        finally:
            self._nfgen_family = NFProto.UNSPEC
