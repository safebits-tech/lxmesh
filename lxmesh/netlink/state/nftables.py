from __future__ import annotations

__all__ = ['NFTableState']

import hashlib
import itertools
import json
import logging
import operator
import os
import typing
from collections import deque

import pyroute2  # type: ignore # No stubs
import pyroute2.netlink  # type: ignore # No stubs
import pyroute2.netlink.nfnetlink  # type: ignore # No stubs
from pyroute2.netlink.nfnetlink import nftsocket

from lxmesh.netlink.exceptions import NetlinkError
from lxmesh.netlink.nftables import NFProto, NFTablesRaw
from lxmesh.netlink.state import NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext
from lxmesh.state import StateObject


# FIXME: Replace with type statement in Python 3.12.
TableSpecType: typing.TypeAlias = dict[typing.Literal['table', 'set', 'map', 'chain', 'rule'],
                                       list[dict[str, typing.Any]]]


class NFTableState(StateObject[NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext]):
    family: str
    name:   str
    spec:   TableSpecType | None    = StateObject.field(key=False)

    @classmethod
    def init(cls, context: NetlinkInitialiseContext) -> None:
        for family in NFProto:
            if family == NFProto.UNSPEC:
                continue
            context.register_nf_subscription(cls.event_table, pyroute2.netlink.nfnetlink.NFNLGRP_NFTABLES,
                                             family=family, operation=(pyroute2.netlink.nfnetlink.NFNL_SUBSYS_NFTABLES << 8) | nftsocket.NFT_MSG_NEWTABLE)
            context.register_nf_subscription(cls.event_table, pyroute2.netlink.nfnetlink.NFNLGRP_NFTABLES,
                                             family=family, operation=(pyroute2.netlink.nfnetlink.NFNL_SUBSYS_NFTABLES << 8) | nftsocket.NFT_MSG_DELTABLE)
            context.register_nf_subscription(cls.event_rule, pyroute2.netlink.nfnetlink.NFNLGRP_NFTABLES,
                                             family=family, operation=(pyroute2.netlink.nfnetlink.NFNL_SUBSYS_NFTABLES << 8) | nftsocket.NFT_MSG_NEWRULE)
            context.register_nf_subscription(cls.event_rule, pyroute2.netlink.nfnetlink.NFNLGRP_NFTABLES,
                                             family=family, operation=(pyroute2.netlink.nfnetlink.NFNL_SUBSYS_NFTABLES << 8) | nftsocket.NFT_MSG_DELRULE)

    @classmethod
    def event_table(cls, context: NetlinkEventContext, table: pyroute2.netlink.nlmsg) -> None:
        family = str(NFProto(table['nfgen_family'])).lower()
        name = table.get_attr('NFTA_TABLE_NAME')
        obj = cls(family=family, name=name, spec=None)
        active_obj = context.active.get(obj)
        if active_obj is None:
            return
        try:
            nf_table = context.nf_table_map[obj.family, obj.name]
        except KeyError:
            raise NetlinkError("got event for known netfilter table '{} {}' without associated internal state".format(obj.family, obj.name)) from None

        userdata = table.get_attr('NFTA_TABLE_USERDATA')
        if userdata == '42:00':
            logging.debug("Ignoring intermediary event for netfilter table '{} {}'.".format(obj.family, obj.name))
            return
        if userdata is not None:
            try:
                comment = NFTablesRaw.parse_comment(userdata)
            except ValueError:
                comment = None
        else:
            comment = None

        if table['header']['type'] & 0xFF == nftsocket.NFT_MSG_NEWTABLE:
            if comment != nf_table.comment:
                if comment is not None:
                    try:
                        signature, generation_str = comment.split(':', 1)
                        generation = int(generation_str)
                    except ValueError:
                        pass
                    else:
                        if signature == nf_table.signature and generation < nf_table.generation:
                            # Ignore previous events we may have generated.
                            return
                logging.debug("Forcing re-addition of netfilter table '{} {}' due to different table creation.".format(obj.family, obj.name))
                context.active.remove_if_exact(active_obj)
                context.pending_add.add(active_obj)
        elif table['header']['type'] & 0xFF == nftsocket.NFT_MSG_DELTABLE:
            if comment == nf_table.comment:
                logging.debug("Forcing re-addition of netfilter table '{} {}' due to active table deletion.".format(obj.family, obj.name))
                context.active.remove_if_exact(active_obj)
                context.pending_add.add(active_obj)

    @classmethod
    def event_rule(cls, context: NetlinkEventContext, rule: pyroute2.netlink.nlmsg) -> None:
        family = str(NFProto(rule['nfgen_family'])).lower()
        table_name = rule.get_attr('NFTA_RULE_TABLE')
        obj = cls(family=family, name=table_name, spec=None)
        active_obj = context.active.get(obj)
        if active_obj is None:
            return
        try:
            nf_table = context.nf_table_map[obj.family, obj.name]
        except KeyError:
            raise NetlinkError("got event for known netfilter table '{} {}' without associated internal state".format(obj.family, obj.name)) from None

        userdata = rule.get_attr('NFTA_RULE_USERDATA')
        if userdata is not None:
            try:
                comment = NFTablesRaw.parse_comment(userdata)
            except ValueError:
                comment = None
        else:
            comment = None

        if rule['header']['type'] & 0xFF == nftsocket.NFT_MSG_NEWRULE:
            if comment != nf_table.comment:
                if comment is not None:
                    try:
                        signature, generation_str = comment.split(':', 1)
                        generation = int(generation_str)
                    except ValueError:
                        pass
                    else:
                        if signature == nf_table.signature and generation < nf_table.generation:
                            # Ignore previous events we may have generated.
                            return
                logging.debug("Forcing re-addition of netfilter table '{} {}' due to different rule creation.".format(obj.family, obj.name))
                context.active.remove_if_exact(active_obj)
                context.pending_add.add(active_obj)
        elif rule['header']['type'] & 0xFF == nftsocket.NFT_MSG_DELRULE:
            if comment == nf_table.comment:
                logging.debug("Forcing re-addition of netfilter table '{} {}' due to active rule deletion.".format(obj.family, obj.name))
                context.active.remove_if_exact(active_obj)
                context.pending_add.add(active_obj)

    @staticmethod
    def nf_object_signature(object: typing.Any) -> bytes:
        pending = deque([object])
        signature = hashlib.sha3_256()
        while pending:
            obj = pending.popleft()
            if isinstance(obj, dict):
                items = list(obj.items())
                items.sort(key=operator.itemgetter(0))
                pending.appendleft('}')
                pending.extendleft(itertools.chain.from_iterable(items))
                pending.appendleft('{')
            elif isinstance(obj, list):
                pending.appendleft(']')
                pending.extendleft(reversed(obj))
                pending.appendleft('[')
            else:
                signature.update(json.dumps(obj).encode('utf-8'))
        return signature.digest()

    @classmethod
    def load(cls, context: NetlinkLoadContext) -> None:
        # FIXME: once libnftables supports comment fields for tables.
        # rc, output, error = nft.json_cmd({'nftables': [{'list': {'tables': {}}}]})
        # if rc != 0:
        #     raise NetlinkError("failed to list netfilter tables: {}".format(error))

        # existing_tables = []
        # for object_type, object_desc in itertools.chain.from_iterable(map(lambda obj: obj.items(), output['nftables'])):
        #     if object_type == 'table':
        #         obj = context.pending_add.get(cls(family=object_desc['family'], name=object_desc['name'], spec=None))
        #         if obj is None:
        #             # We do not delete tables we do not care about
        #             continue
        #         existing_tables.append(obj)

        existing_tables: list[tuple[NFTableState, str | None]] = []
        try:
            for family, table_name, table_comment in context.nft_raw.get_tables():
                family_name = str(NFProto(family)).lower()
                obj = context.pending_add.get(cls(family=family_name, name=table_name, spec=None))
                if obj is None:
                    # We do not delete tables we do not care about
                    continue
                existing_tables.append((obj, table_comment))
        except pyroute2.NetlinkError as e:
            raise NetlinkError("failed to enumerate netfilter tables: {} ({})".format(os.strerror(e.code), e.code)) from None

        for obj, obj_comment in existing_tables:
            if obj.spec is None:
                logging.critical("Cannot manage netfilter table without specification (this is a bug).")
                continue
            try:
                nf_table = context.nf_table_map[obj.family, obj.name]
            except KeyError:
                logging.critical("Requested addition of netfilter table '{} {}' without associated internal state.".format(obj.family, obj.name))
                continue
            commands = [
                {
                    'list': {
                        'table': {
                            'family': obj.family,
                            'name': obj.name,
                        }
                    }
                }
            ]
            rc, output, error = context.nft.json_cmd({'nftables': commands})
            if rc != 0:
                # Unfortunately, error codes such as 'ENOENT' are not returned in a
                # programming-friendly way.
                logging.debug("Failed to list netfilter table '{} {}': {}.".format(obj.family, obj.name, error))
                continue

            table_signature = hashlib.sha3_256(json.dumps(obj.spec).encode('utf-8')).hexdigest()
            remaining_objects: dict[str, set[bytes]] = {}
            rule_previous_signature: dict[bytes, bytes | None] = {}
            seen_chains = set()
            previous_chain = None
            previous_signature = None
            for object_type, object_descriptions in obj.spec.items():
                remaining_objects[object_type] = set()
                for object_desc in object_descriptions:
                    if not object_desc:
                        continue
                    signature = cls.nf_object_signature(object_desc)
                    remaining_objects[object_type].add(signature)
                    if object_type == 'rule':
                        if object_desc['chain'] == previous_chain:
                            rule_previous_signature[signature] = previous_signature
                        elif object_desc['chain'] in seen_chains:
                            raise NetlinkError("netfilter rule for chain '{}' in table '{} {}' not grouped with other rules (this is a bug)".format(object_desc['chain'], obj.family, obj.name))
                        else:
                            rule_previous_signature[signature] = None
                            seen_chains.add(object_desc['chain'])
                        previous_chain = object_desc['chain']
                        previous_signature = signature
            table_generation = None
            expected_comment = None
            previous_signature_by_chain: dict[str, bytes] = {}
            for object_type, object_desc in itertools.chain.from_iterable(map(operator.methodcaller('items'), output['nftables'])):
                if object_type == 'table':
                    if object_desc.get('family') != obj.family:
                        continue
                    if object_desc.get('name') != obj.name:
                        continue
                    try:
                        expected_comment = obj_comment
                        if expected_comment is None:
                            raise KeyError
                        # FIXME: once libnftables supports comment fields for tables.
                        # expected_comment = object_desc['comment']
                        comment_signature, generation = expected_comment.split(':', 1)
                        table_generation = int(generation)
                    except KeyError:
                        logging.warning("Netfilter table '{} {}' does not have a comment field.".format(obj.family, obj.name))
                        break
                    except ValueError:
                        logging.warning("Netfilter table '{} {}' does not have a valid comment field: {}.".format(obj.family, obj.name, object_desc['comment']))
                        break
                    else:
                        if comment_signature != table_signature:
                            logging.debug("Netfilter table '{} {}' has a different signature and requires updating.".format(obj.family, obj.name))
                            break
                else:
                    if object_desc.pop('family', None) != obj.family:
                        continue
                    if object_desc.pop('table', None) != obj.name:
                        continue
                    try:
                        object_signatures = remaining_objects[object_type]
                    except KeyError:
                        logging.warning("Netfilter table '{} {}' contains unexpected object of type '{}': {}.".format(obj.family, obj.name, object_type, object_desc))
                        break
                    try:
                        # FIXME: once libnftables supports comment fields for all object types.
                        if False and object_desc['comment'] != expected_comment:
                            logging.warning("Netfilter '{}' object in table '{} {}' has a different comment compared to the table.".format(object_type, obj.family, obj.name))
                            break
                    except KeyError:
                        logging.warning("Netfilter '{}' object in table '{} {}' does not have a comment field.".format(object_type, obj.family, obj.name))
                        break
                    else:
                        object_desc.pop('comment', None)
                        object_desc.pop('handle', None)
                        match object_type:
                            case 'set' | 'map':
                                object_desc.pop('elem', None)
                        signature = cls.nf_object_signature(object_desc)
                        try:
                            object_signatures.remove(signature)
                        except KeyError:
                            logging.warning("Netfilter table '{} {}' contains unexpected object of type '{}': {}.".format(obj.family, obj.name, object_type, object_desc))
                            break
                        if object_type == 'rule':
                            expected_previous_signature = rule_previous_signature[signature]
                            if previous_signature_by_chain.get(object_desc['chain']) != expected_previous_signature:
                                logging.warning("Netfilter rule in table '{} {}' expected to follow a different rule: {}.".format(obj.family, obj.name, object_desc))
                                break
                            previous_signature_by_chain[object_desc['chain']] = signature
            else:
                # All objects found match our expectations, now ensure that
                # there are no missing objects.
                if expected_comment is not None and table_generation is not None and not any(remaining_objects.values()):
                    logging.debug("Marking netfilter table '{} {}' as active.".format(obj.family, obj.name))
                    context.pending_add.remove_must_match(obj)
                    context.active.add(obj)
                    nf_table.comment = expected_comment
                    nf_table.signature = table_signature
                    nf_table.generation = table_generation
                    continue
            if table_generation is not None:
                nf_table.generation = table_generation
            logging.debug("Marking netfilter table '{} {}' as requiring addition.".format(obj.family, obj.name))

    def add(self, context: NetlinkOperationContext) -> None:
        if self.spec is None:
            raise NetlinkError("cannot add netfilter table without specification")
        try:
            nf_table = context.nf_table_map[self.family, self.name]
        except KeyError:
            raise NetlinkError("requested addition of netfilter table '{} {}' without associated internal state".format(self.family, self.name)) from None

        nf_table.signature = hashlib.sha3_256(json.dumps(self.spec).encode('utf-8')).hexdigest()
        nf_table.generation += 1
        nf_table.comment = '{}:{}'.format(nf_table.signature, nf_table.generation)

        try:
            context.nft_raw.add_table(NFProto[self.family.upper()], self.name, comment=nf_table.comment, replace=True)
        except pyroute2.NetlinkError as e:
            raise NetlinkError("failed to add netfilter table '{} {}': {} ({})".format(self.family, self.name, os.strerror(e.code), e.code)) from None

        commands = [
            # FIXME: once libnftables has support for table comments.
            # FIXME: kernel 6.3 and newer libnftables has support for destroy,
            # which ignores inexistent objects.
            # {
            #     'add': {
            #         'table': {
            #             'family': self.family,
            #             'name': self.name,
            #         }
            #     }
            # },
            # {
            #     'delete': {
            #         'table': {
            #             'family': self.family,
            #             'name': self.name,
            #         }
            #     }
            # },
            # {
            #     'create': {
            #         'table': {
            #             'family': self.family,
            #             'name': self.name,
            #             'comment': nf_table.comment,
            #         }
            #     }
            # }
        ]
        for object_type, object_descriptions in self.spec.items():
            for object_desc in object_descriptions:
                if not object_desc:
                    continue
                new_object_desc = object_desc.copy()
                new_object_desc['family'] = self.family
                new_object_desc['table'] = self.name
                new_object_desc['comment'] = nf_table.comment
                match object_type:
                    case 'rule':
                        command = 'add'
                    case _:
                        command = 'create'
                commands.append({command: {object_type: new_object_desc}})

        rc, output, error = context.nft.json_cmd({'nftables': commands})
        if rc != 0:
            raise NetlinkError("failed to create netfilter table '{} {}': {}".format(self.family, self.name, error))
        else:
            logging.info("Added netfilter table '{} {}'.".format(self.family, self.name))

    # FIXME: annotate 'old' with typing.Self in Python 3.11+.
    def modify(self, context: NetlinkOperationContext, old: NFTableState) -> None:
        self.add(context)

    def delete(self, context: NetlinkOperationContext) -> None:
        try:
            context.nft_raw.del_table(NFProto[self.family.upper()], self.name)
        except pyroute2.NetlinkError as e:
            raise NetlinkError("failed to delete netfilter table '{} {}': {} ({})".format(self.family, self.name, os.strerror(e.code), e.code)) from None
        else:
            logging.info("Deleted netfilter table '{} {}'.".format(self.family, self.name))
