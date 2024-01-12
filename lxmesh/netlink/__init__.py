__all__ = ['NetlinkManager', 'NetlinkState', 'NetlinkSVIConfig']

import ipaddress
import logging
import os

import nftables as libnftables  # type: ignore # No stubs.

import lxmesh.netlink.fixup  # noqa: FIXME this won't be necessary at some point, but must come first
from lxmesh.netlink.constants import NFTablesSets
from lxmesh.netlink.iproute import IPRouteExtended
from lxmesh.netlink.monitor import NetlinkMonitor
from lxmesh.netlink.nftables import NFProto, NFTablesRaw
from lxmesh.netlink.state import NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext, NetlinkSVI, NetlinkSVIConfig, NFTable
from lxmesh.netlink.state.address import ValidatedAddressState
from lxmesh.netlink.state.device import DeviceState
from lxmesh.netlink.state.fdb import FDBEntryState
from lxmesh.netlink.state.mark import MarkState
from lxmesh.netlink.state.mdb import MDBEntryState
from lxmesh.netlink.state.neighbour import NeighbourState
from lxmesh.netlink.state.nftables import NFTableState
from lxmesh.netlink.state.route import RouteState
from lxmesh.netlink.state.service import ServiceState
from lxmesh.netlink.state.svi import SVIState
from lxmesh.netlink.state.vxlan import VXLANState
from lxmesh.state import StateManager, StateTable


class NetlinkState(StateTable[NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext]):
    NFTable             = NFTableState

    SVI                 = SVIState
    VXLAN               = VXLANState
    Device              = DeviceState

    Route               = RouteState
    FDBEntry            = FDBEntryState
    MDBEntry            = MDBEntryState
    Neighbour           = NeighbourState

    Mark                = MarkState
    Service             = ServiceState
    ValidatedAddress    = ValidatedAddressState


class NetlinkManager(StateManager[NetlinkEventContext, NetlinkInitialiseContext, NetlinkLoadContext, NetlinkOperationContext], state_type=NetlinkState):
    def __init__(self, *,
                 netlink_monitor: NetlinkMonitor,
                 table_name: str,
                 default_svi_config: NetlinkSVIConfig,
                 svi_config: dict[str, NetlinkSVIConfig] = {},
                 ip4_all_nodes_address: ipaddress.IPv4Address | None = None,
                 ip6_all_nodes_address: ipaddress.IPv6Address | None = None):
        self.table_name = table_name
        self.default_svi_config = default_svi_config
        self.svi_config = svi_config
        self.ip4_all_nodes_address = ip4_all_nodes_address
        self.ip6_all_nodes_address = ip6_all_nodes_address

        self.svi_map: dict[str, NetlinkSVI] = {}
        self.nf_table_map: dict[tuple[str, str], NFTable] = {}

        self.instance_id = os.urandom(16)

        init_context = NetlinkInitialiseContext(manager=self,
                                                event_context_factory=self.event_context_factory,
                                                netlink_monitor=netlink_monitor,
                                                table_name=self.table_name)
        super().__init__(init_context=init_context)

        have_multicast = default_svi_config.multicast or any(config.multicast for config in svi_config.values())

        nf_table_bridge_spec = {
            'set': [
                {
                    'name': str(NFTablesSets.svis),
                    'type': 'ifname'
                },
                {
                    'name': str(NFTablesSets.multicast_svis),
                    'type': 'ifname'
                },
                {
                    'name': str(NFTablesSets.eth_addresses),
                    'type': ['ifname', 'ether_addr'],
                },
                {
                    'name': str(NFTablesSets.ip4_addresses),
                    'type': ['ifname', 'ipv4_addr'],
                },
                {
                    'name': str(NFTablesSets.ip6_addresses),
                    'type': ['ifname', 'ipv6_addr'],
                },
                {
                    'name': str(NFTablesSets.in_services),
                    'type': ['ifname', 'inet_proto', 'inet_service'],
                },
                {
                    'name': str(NFTablesSets.out_services),
                    'type': ['ifname', 'inet_proto', 'inet_service'],
                },
            ],
            'map': [
                {
                    'name': str(NFTablesSets.marks),
                    'type': 'ifname',
                    'map': 'mark',
                },
            ],
            'chain': [
                {
                    'name': 'prerouting',
                    'type': 'filter',
                    'hook': 'prerouting',
                    'prio': -190,  # A priority higher than -200 (filter) is needed, because that is what conntrack hooks at (NF_IP_PRI_CONNTRACK).
                    'policy': 'drop',
                },
                {
                    'name': 'forward',
                    'type': 'filter',
                    'hook': 'forward',
                    'prio': -200,  # filter
                    'policy': 'accept',
                },
                {
                    'name': 'output',
                    'type': 'filter',
                    'hook': 'output',
                    'prio': -200,  # filter
                    'policy': 'accept',
                },
                {
                    'name': 'postrouting',
                    'type': 'filter',
                    'hook': 'postrouting',
                    'prio': -200,  # filter
                    'policy': 'drop',
                }
            ],
            'rule': [
                # === prerouting ===
                # meta ibrname != @svis accept
                {
                    'chain': 'prerouting',
                    'expr': [{'match': {'left': {'meta': {'key': 'ibrname'}},
                                        'op': '!=',
                                        'right': '@' + str(NFTablesSets.svis)}},
                             {'accept': None}],
                },
                # meta iifkind "vxlan" accept
                {
                    'chain': 'prerouting',
                    'expr': [{'match': {'left': {'meta': {'key': 'iifkind'}},
                                        'op': '==',
                                        'right': 'vxlan'}},
                             {'accept': None}],
                },
                # meta iifname . ether saddr != @eth-addresses drop
                {
                    'chain': 'prerouting',
                    'expr': [{'match': {'left': {'concat': [{'meta': {'key': 'iifname'}},
                                                            {'payload': {'protocol': 'ether', 'field': 'saddr'}}]},
                                        'op': '!=',
                                        'right': '@' + str(NFTablesSets.eth_addresses)}},
                             {'drop': None}]
                },
                # meta mark set meta iifname map @marks
                {
                    'chain': 'prerouting',
                    'expr': [{'mangle': {'key': {'meta': {'key': 'mark'}},
                                         'value': {'map': {'data': '@' + str(NFTablesSets.marks),
                                                           'key': {'meta': {'key': 'iifname'}}}}}}],
                },
                # ct state related,established accept
                {
                    'chain': 'prerouting',
                    'expr': [{'match': {'left': {'ct': {'key': 'state'}},
                                        'op': 'in',
                                        'right': ['established', 'related']}},
                             {'accept': None}],
                },
                # ct state invalid drop
                {
                    'chain': 'prerouting',
                    'expr': [{'match': {'left': {'ct': {'key': 'state'}},
                                        'op': 'in',
                                        'right': 'invalid'}},
                             {'drop': None}],
                },
                # ip daddr [IP4_ALL_NODES_ADDRESS] drop
                {
                    'chain': 'prerouting',
                    'expr': [{'match': {'left': {'payload': {'protocol': 'ip', 'field': 'daddr'}},
                                        'op': '==',
                                        'right': str(self.ip4_all_nodes_address)}},
                             {'drop': None}],
                } if self.ip4_all_nodes_address is not None else {},
                # ip6 daddr [IP6_ALL_NODES_ADDRESS] drop
                {
                    'chain': 'prerouting',
                    'expr': [{'match': {'left': {'payload': {'protocol': 'ip6', 'field': 'daddr'}},
                                        'op': '==',
                                        'right': str(self.ip6_all_nodes_address)}},
                             {'drop': None}],
                } if self.ip6_all_nodes_address is not None else {},
                # ether type arp accept
                {
                    'chain': 'prerouting',
                    'expr': [{'match': {'left': {'payload': {'protocol': 'ether', 'field': 'type'}},
                                        'op': '==',
                                        'right': 'arp'}},
                             {'accept': None}],
                },
                # ip saddr != 0.0.0.0 meta iifname . ip saddr != @ip4-addresses drop
                {
                    'chain': 'prerouting',
                    'expr': [{'match': {'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}},
                                        'op': '!=',
                                        'right': '0.0.0.0'}},
                             {'match': {'left': {'concat': [{'meta': {'key': 'iifname'}},
                                                            {'payload': {'protocol': 'ip', 'field': 'saddr'}}]},
                                        'op': '!=',
                                        'right': '@' + str(NFTablesSets.ip4_addresses)}},
                             {'drop': None}]
                },
                # ip6 saddr != :: meta iifname . ip6 saddr != @ip6-addresses drop
                {
                    'chain': 'prerouting',
                    'expr': [{'match': {'left': {'payload': {'protocol': 'ip6', 'field': 'saddr'}},
                                        'op': '!=',
                                        'right': '::'}},
                             {'match': {'left': {'concat': [{'meta': {'key': 'iifname'}},
                                                            {'payload': {'protocol': 'ip6', 'field': 'saddr'}}]},
                                        'op': '!=',
                                        'right': '@' + str(NFTablesSets.ip6_addresses)}},
                             {'drop': None}],
                },
                # meta ibrname @multicast-svis ether type ip igmp type {
                #   membership-report-v1,
                #   membership-report-v2,
                #   leave-group
                #   membership-report-v3,
                # } accept
                {
                    'chain': 'prerouting',
                    'expr': [{'match': {'left': {'meta': {'key': 'ibrname'}},
                                        'op': '==',
                                        'right': '@' + str(NFTablesSets.multicast_svis)}},
                             {'match': {'left': {'payload': {'protocol': 'ether', 'field': 'type'}},
                                        'op': '==',
                                        'right': 'ip'}},
                             {'match': {'left': {'payload': {'protocol': 'igmp', 'field': 'type'}},
                                        'op': '==',
                                        'right': {'set': ['membership-report-v1',
                                                          'membership-report-v2',
                                                          'leave-group',
                                                          'membership-report-v3']}}},
                             {'accept': None}],
                } if have_multicast else {},
                # ip daddr 224.0.0.0/24 drop
                {
                    'chain': 'prerouting',
                    'expr': [{'match': {'left': {'payload': {'protocol': 'ip', 'field': 'daddr'}},
                                        'op': '==',
                                        'right': {'prefix': {'addr': '224.0.0.0', 'len': 24}}}},
                             {'drop': None}]
                },
                # icmp type echo-request accept
                {
                    'chain': 'prerouting',
                    'expr': [{'match': {'left': {'payload': {'protocol': 'icmp', 'field': 'type'}},
                                        'op': '==',
                                        'right': 'echo-request'}},
                             {'accept': None}],
                },
                # FIXME: Normally, this would only be allowed from
                # @multicast-svis, but the kernel does not perform ND proxy the
                # same way as ARP proxy. In particular, for instances on the
                # same supervisor, the kernel will NOT perform ND proxy.
                # Therefore, these must be allowed to exchange neighbour
                # solicitation and neighbour advertisement messages, which use
                # multicast. See function br_do_suppress_nd() in
                # net/bridge/br_arp_nd_proxy.c.
                # icmpv6 type {
                #   mld-listener-report,
                #   mld-listener-done,
                #   mld2-listener-report
                # } accept
                {
                    'chain': 'prerouting',
                    'expr': [{'match': {'left': {'payload': {'protocol': 'icmpv6', 'field': 'type'}},
                                        'op': '==',
                                        'right': {'set': ['mld-listener-report',
                                                          'mld-listener-done',
                                                          'mld2-listener-report']}}},
                             {'accept': None}],
                },
                # ip6 daddr { ff02::1, ff02::16 } drop
                {
                    'chain': 'prerouting',
                    'expr': [{'match': {'left': {'payload': {'protocol': 'ip6', 'field': 'daddr'}},
                                        'op': '==',
                                        'right': {'set': ['ff02::1', 'ff02::16']}}},
                             {'drop': None}]
                },
                # icmpv6 type {
                #   echo-request,
                #   nd-router-solicit,
                #   nd-neighbor-solicit,
                #   nd-neighbor-advert,
                # } accept
                {
                    'chain': 'prerouting',
                    'expr': [{'match': {'left': {'payload': {'protocol': 'icmpv6', 'field': 'type'}},
                                        'op': '==',
                                        'right': {'set': ['echo-request',
                                                          'nd-router-solicit',
                                                          'nd-neighbor-solicit',
                                                          'nd-neighbor-advert']}}},
                             {'accept': None}],
                },
                # FIXME: This will be possible with nftables 1.0.9. Also, drop
                # nd-neighbor-advert from rule above.
                #
                # Unfortunately, without this, spoofing neighbour
                # advertisements is possible and, therefore, intercepting
                # communication.
                #
                # With nftables 1.0.3, raw payload expressions can be used in
                # concatenations.
                #
                # icmpv6 type nd-neighbor-advert meta iifname . icmpv6 taddr @ip6-addresses accept
                # {
                #     'chain': 'prerouting',
                #     'expr': [{'match': {'left': {'payload': {'protocol': 'icmpv6', 'field': 'type'}},
                #                         'op': '==',
                #                         'right': 'nd-neighbor-advert'}},
                #              {'match': {'left': {'concat': [{'meta': {'key': 'iifname'}},
                #                                             {'payload': {'protocol': 'icmpv6', 'field': 'taddr'}}]},
                #                         'op': '==',
                #                         'right': '@' + str(NFTablesSets.ip6_addresses)}},
                #              {'accept': None}],
                # },
                # meta protocol ip udp sport 68 udp dport 67 accept
                {
                    'chain': 'prerouting',
                    'expr': [{'match': {'left': {'meta': {'key': 'protocol'}},
                                        'op': '==',
                                        'right': 'ip'}},
                             {'match': {'left': {'payload': {'protocol': 'udp', 'field': 'sport'}},
                                        'op': '==',
                                        'right': 68}},
                             {'match': {'left': {'payload': {'protocol': 'udp', 'field': 'dport'}},
                                        'op': '==',
                                        'right': 67}},
                             {'accept': None}],
                },
                # meta protocol ip6 udp sport 546 udp dport 547 accept
                {
                    'chain': 'prerouting',
                    'expr': [{'match': {'left': {'meta': {'key': 'protocol'}},
                                        'op': '==',
                                        'right': 'ip6'}},
                             {'match': {'left': {'payload': {'protocol': 'udp', 'field': 'sport'}},
                                        'op': '==',
                                        'right': 546}},
                             {'match': {'left': {'payload': {'protocol': 'udp', 'field': 'dport'}},
                                        'op': '==',
                                        'right': 547}},
                             {'accept': None}],
                },
                # meta iifname . meta l4proto . th dport @out-services accept
                {
                    'chain': 'prerouting',
                    'expr': [{'match': {'left': {'concat': [{'meta': {'key': 'iifname'}},
                                                            {'meta': {'key': 'l4proto'}},
                                                            {'payload': {'protocol': 'th', 'field': 'dport'}}]},
                                        'op': '==',
                                        'right': '@' + str(NFTablesSets.out_services)}},
                             {'accept': None}]
                },
                # policy drop

                # === forward ===
                # meta ibrname != @svis accept
                {
                    'chain': 'forward',
                    'expr': [{'match': {'left': {'meta': {'key': 'ibrname'}},
                                        'op': '!=',
                                        'right': '@' + str(NFTablesSets.svis)}},
                             {'accept': None}],
                },
                # ct state related,established accept
                {
                    'chain': 'forward',
                    'expr': [{'match': {'left': {'ct': {'key': 'state'}},
                                        'op': 'in',
                                        'right': ['established', 'related']}},
                             {'accept': None}],
                },
                # ip saddr 0.0.0.0 drop
                {
                    'chain': 'forward',
                    'expr': [{'match': {'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}},
                                        'op': '==',
                                        'right': '0.0.0.0'}},
                             {'drop': None}],
                },
                # ip6 saddr :: drop
                {
                    'chain': 'forward',
                    'expr': [{'match': {'left': {'payload': {'protocol': 'ip6', 'field': 'saddr'}},
                                        'op': '==',
                                        'right': '::'}},
                             {'drop': None}],
                },
                # meta oifkind "vxlan" ether type ip igmp type {
                #   membership-report-v1,
                #   membership-report-v2,
                #   leave-group
                #   membership-report-v3,
                # } accept
                {
                    'chain': 'forward',
                    'expr': [{'match': {'left': {'meta': {'key': 'oifkind'}},
                                        'op': '==',
                                        'right': 'vxlan'}},
                             {'match': {'left': {'payload': {'protocol': 'ether', 'field': 'type'}},
                                        'op': '==',
                                        'right': 'ip'}},
                             {'match': {'left': {'payload': {'protocol': 'igmp', 'field': 'type'}},
                                        'op': '==',
                                        'right': {'set': ['membership-report-v1',
                                                          'membership-report-v2',
                                                          'leave-group',
                                                          'membership-report-v3']}}},
                             {'accept': None}],
                } if have_multicast else {},
                # meta protocol ip meta l4proto igmp drop
                {
                    'chain': 'forward',
                    'expr': [{'match': {'left': {'meta': {'key': 'protocol'}},
                                        'op': '==',
                                        'right': 'ip'}},
                             {'match': {'left': {'meta': {'key': 'l4proto'}},
                                        'op': '==',
                                        'right': 'igmp'}},
                             {'drop': None}],
                },
                # Normally, only echo-request would be allowed here. However, it
                # seems that destination-unreachable ICMP messages (including
                # fragmentation-needed) are not matched by conntrack.
                # icmp type != { destination-unreachable, echo-request } drop
                {
                    'chain': 'forward',
                    'expr': [{'match': {'left': {'payload': {'protocol': 'icmp', 'field': 'type'}},
                                        'op': '!=',
                                        'right': {'set': ['destination-unreachable',
                                                          'echo-request']}}},
                             {'drop': None}],
                },
                # meta obrname @multicast-svis meta oifkind "vxlan" icmpv6 type {
                #   mld-listener-report,
                #   mld-listener-done,
                #   mld2-listener-report
                # } accept
                {
                    'chain': 'forward',
                    'expr': [{'match': {'left': {'meta': {'key': 'obrname'}},
                                        'op': '==',
                                        'right': '@' + str(NFTablesSets.multicast_svis)}},
                             {'match': {'left': {'meta': {'key': 'oifkind'}},
                                        'op': '==',
                                        'right': 'vxlan'}},
                             {'match': {'left': {'payload': {'protocol': 'icmpv6', 'field': 'type'}},
                                        'op': '==',
                                        'right': {'set': ['mld-listener-report',
                                                          'mld-listener-done',
                                                          'mld2-listener-report']}}},
                             {'accept': None}],
                } if have_multicast else {},
                # FIXME: Normally, only echo-request ICMPv6 messages would be
                # allowed here, but the kernel does not perform ND proxy the
                # same way as ARP proxy. In particular, for instances on the
                # same supervisor, the kernel will NOT perform ND proxy.
                # Therefore, these must be allowed to exchange neighbour
                # solicitation and neighbour advertisement messages. The good
                # news is these use multicast, so no flooding takes place. See
                # function br_do_suppress_nd() in net/bridge/br_arp_nd_proxy.c.
                #
                # Additionally, destination-unreachable and packet-too-big are
                # not matched by conntrack, for some reason, so they need to be
                # added here.
                # icmpv6 type != {
                #   destination-unreachable,
                #   packet-too-big,
                #   echo-request,
                #   nd-neighbor-solicit,
                #   nd-neighbor-advert,
                # } drop
                {
                    'chain': 'forward',
                    'expr': [{'match': {'left': {'payload': {'protocol': 'icmpv6', 'field': 'type'}},
                                        'op': '!=',
                                        'right': {'set': ['destination-unreachable',
                                                          'packet-too-big',
                                                          'echo-request',
                                                          'nd-neighbor-solicit',
                                                          'nd-neighbor-advert']}}},
                             {'drop': None}],
                },
                # meta protocol ip udp sport 68 udp dport 67 drop
                {
                    'chain': 'forward',
                    'expr': [{'match': {'left': {'meta': {'key': 'protocol'}},
                                        'op': '==',
                                        'right': 'ip'}},
                             {'match': {'left': {'payload': {'protocol': 'udp', 'field': 'sport'}},
                                        'op': '==',
                                        'right': 68}},
                             {'match': {'left': {'payload': {'protocol': 'udp', 'field': 'dport'}},
                                        'op': '==',
                                        'right': 67}},
                             {'drop': None}],
                },
                # meta protocol ip6 udp sport 546 udp dport 547 drop
                {
                    'chain': 'forward',
                    'expr': [{'match': {'left': {'meta': {'key': 'protocol'}},
                                        'op': '==',
                                        'right': 'ip6'}},
                             {'match': {'left': {'payload': {'protocol': 'udp', 'field': 'sport'}},
                                        'op': '==',
                                        'right': 546}},
                             {'match': {'left': {'payload': {'protocol': 'udp', 'field': 'dport'}},
                                        'op': '==',
                                        'right': 547}},
                             {'drop': None}],
                },
                # policy accept

                # === output ===
                # meta obrname != @svis accept
                {
                    'chain': 'output',
                    'expr': [{'match': {'left': {'meta': {'key': 'obrname'}},
                                        'op': '!=',
                                        'right': '@' + str(NFTablesSets.svis)}},
                             {'accept': None}],
                },
                # ip daddr [IP4_ALL_NODES_ADDRESS] ip daddr set 224.0.0.1 ether daddr set 01:00:5e:00:00:01
                {
                    'chain': 'output',
                    'expr': [{'match': {'left': {'payload': {'protocol': 'ip', 'field': 'daddr'}},
                                        'op': '==',
                                        'right': str(self.ip4_all_nodes_address)}},
                             {'mangle': {'key': {'payload': {'protocol': 'ip', 'field': 'daddr'}},
                                         'value': '224.0.0.1'}},
                             {'mangle': {'key': {'payload': {'protocol': 'ether', 'field': 'daddr'}},
                                         'value': '01:00:5e:00:00:01'}}],
                } if self.ip4_all_nodes_address is not None else {},
                # ip6 daddr [IP6_ALL_NODES_ADDRESS] ip6 daddr set ff02::1 ether daddr set 33:33:00:00:00:01
                {
                    'chain': 'output',
                    'expr': [{'match': {'left': {'payload': {'protocol': 'ip6', 'field': 'daddr'}},
                                        'op': '==',
                                        'right': str(self.ip6_all_nodes_address)}},
                             {'mangle': {'key': {'payload': {'protocol': 'ip6', 'field': 'daddr'}},
                                         'value': 'ff02::1'}},
                             {'mangle': {'key': {'payload': {'protocol': 'ether', 'field': 'daddr'}},
                                         'value': '33:33:00:00:00:01'}}],
                } if self.ip6_all_nodes_address is not None else {},
                # meta oifkind != "vxlan" accept
                {
                    'chain': 'output',
                    'expr': [{'match': {'left': {'meta': {'key': 'oifkind'}},
                                        'op': '!=',
                                        'right': 'vxlan'}},
                             {'accept': None}],
                },
                # icmpv6 type != {
                #   destination-unreachable,
                #   packet-too-big,
                #   time-exceeded,
                #   parameter-problem,
                #   echo-request,
                #   echo-reply,
                #   nd-neighbor-solicit,
                #   nd-neighbor-advert
                # } drop
                {
                    'chain': 'output',
                    'expr': [{'match': {'left': {'payload': {'protocol': 'icmpv6', 'field': 'type'}},
                                        'op': '!=',
                                        'right': {'set': ['destination-unreachable',
                                                          'packet-too-big',
                                                          'time-exceeded',
                                                          'parameter-problem',
                                                          'echo-request',
                                                          'echo-reply',
                                                          'nd-neighbor-solicit',
                                                          'nd-neighbor-advert']}}},
                             {'drop': None}],
                },
                # meta protocol ip meta l4proto igmp drop
                {
                    'chain': 'output',
                    'expr': [{'match': {'left': {'meta': {'key': 'protocol'}},
                                        'op': '==',
                                        'right': 'ip'}},
                             {'match': {'left': {'meta': {'key': 'l4proto'}},
                                        'op': '==',
                                        'right': 'igmp'}},
                             {'drop': None}],
                },
                # policy accept

                # === postrouting ===
                # meta obrname != @svis accept
                {
                    'chain': 'postrouting',
                    'expr': [{'match': {'left': {'meta': {'key': 'obrname'}},
                                        'op': '!=',
                                        'right': '@' + str(NFTablesSets.svis)}},
                             {'accept': None}],
                },
                # meta oifkind "vxlan" accept
                {
                    'chain': 'postrouting',
                    'expr': [{'match': {'left': {'meta': {'key': 'oifkind'}},
                                        'op': '==',
                                        'right': 'vxlan'}},
                             {'accept': None}],
                },
                # ct state established,related,untracked accept
                {
                    'chain': 'postrouting',
                    'expr': [{'match': {'left': {'ct': {'key': 'state'}},
                                        'op': 'in',
                                        'right': ['established',
                                                  'related',
                                                  'untracked']}},
                             {'accept': None}],
                },
                # ether type arp accept
                # This rule must sit before a check for conntrack state set to
                # invalid, because the host-generated ARP requests would be
                # caught by the latter.
                {
                    'chain': 'postrouting',
                    'expr': [{'match': {'left': {'payload': {'protocol': 'ether', 'field': 'type'}},
                                        'op': '==',
                                        'right': 'arp'}},
                             {'accept': None}],
                },
                # ct state invalid drop
                {
                    'chain': 'postrouting',
                    'expr': [{'match': {'left': {'ct': {'key': 'state'}},
                                        'op': 'in',
                                        'right': 'invalid'}},
                             {'drop': None}],
                },
                # Normally, only echo-request would be allowed here. However, it
                # seems that destination-unreachable ICMP messages (including
                # fragmentation-needed) are not matched by conntrack.
                # icmp type { destination-unreachable, echo-request } accept
                {
                    'chain': 'postrouting',
                    'expr': [{'match': {'left': {'payload': {'protocol': 'icmp', 'field': 'type'}},
                                        'op': '==',
                                        'right': {'set': ['destination-unreachable',
                                                          'echo-request']}}},
                             {'accept': None}],
                },
                # ether type ip igmp type membership-query accept
                {
                    'chain': 'postrouting',
                    'expr': [{'match': {'left': {'payload': {'protocol': 'ether', 'field': 'type'}},
                                        'op': '==',
                                        'right': 'ip'}},
                             {'match': {'left': {'payload': {'protocol': 'igmp', 'field': 'type'}},
                                        'op': '==',
                                        'right': 'membership-query'}},
                             {'accept': None}],
                },
                # ICMP types destination-unreachable and packet-too-big are not
                # matched by conntrack, for some reason, so they need to be
                # added here.
                # icmpv6 type {
                #   destination-unreachable,
                #   packet-too-big,
                #   echo-request,
                #   mld-listener-query,
                #   nd-router-advert,
                #   nd-neighbor-solicit,
                #   nd-neighbor-advert
                # } accept
                {
                    'chain': 'postrouting',
                    'expr': [{'match': {'left': {'payload': {'protocol': 'icmpv6', 'field': 'type'}},
                                        'op': '==',
                                        'right': {'set': ['destination-unreachable',
                                                          'packet-too-big',
                                                          'echo-request',
                                                          'mld-listener-query',
                                                          'nd-router-advert',
                                                          'nd-neighbor-solicit',
                                                          'nd-neighbor-advert']}}},
                             {'accept': None}],
                },
                # meta protocol ip udp sport 67 udp dport 68 accept
                {
                    'chain': 'postrouting',
                    'expr': [{'match': {'left': {'meta': {'key': 'protocol'}},
                                        'op': '==',
                                        'right': 'ip'}},
                             {'match': {'left': {'payload': {'protocol': 'udp', 'field': 'sport'}},
                                        'op': '==',
                                        'right': 67}},
                             {'match': {'left': {'payload': {'protocol': 'udp', 'field': 'dport'}},
                                        'op': '==',
                                        'right': 68}},
                             {'accept': None}],
                },
                # meta protocol ip6 udp sport 547 udp dport 546 accept
                {
                    'chain': 'postrouting',
                    'expr': [{'match': {'left': {'meta': {'key': 'protocol'}},
                                        'op': '==',
                                        'right': 'ip6'}},
                             {'match': {'left': {'payload': {'protocol': 'udp', 'field': 'sport'}},
                                        'op': '==',
                                        'right': 547}},
                             {'match': {'left': {'payload': {'protocol': 'udp', 'field': 'dport'}},
                                        'op': '==',
                                        'right': 546}},
                             {'accept': None}],
                },
                # meta oifname . meta l4proto . th dport @in-services accept
                {
                    'chain': 'postrouting',
                    'expr': [{'match': {'left': {'concat': [{'meta': {'key': 'oifname'}},
                                                            {'meta': {'key': 'l4proto'}},
                                                            {'payload': {'protocol': 'th', 'field': 'dport'}}]},
                                        'op': '==',
                                        'right': '@' + str(NFTablesSets.in_services)}},
                             {'accept': None}]
                },
                # policy drop
            ],
        }
        obj = NetlinkState.NFTable(family=str(NFProto.BRIDGE).lower(), name=self.table_name, spec=nf_table_bridge_spec)
        self.nf_table_map[obj.family, obj.name] = NFTable()
        self.add(obj)

        nf_table_inet_spec = {
            'set': [
                {
                    'name': str(NFTablesSets.svis),
                    'type': 'ifname'
                },
            ],
            'chain': [
                {
                    'name': 'raw-output',
                    'type': 'filter',
                    'hook': 'output',
                    'prio': -300,  # raw
                    'policy': 'accept',
                } if any([self.ip4_all_nodes_address, self.ip6_all_nodes_address]) else {},
            ],
            'rule': [
                # === raw-output ===
                # meta oifname != @svis accept
                {
                    'chain': 'raw-output',
                    'expr': [{'match': {'left': {'meta': {'key': 'oifname'}},
                                        'op': '!=',
                                        'right': '@' + str(NFTablesSets.svis)}},
                             {'accept': None}],
                } if any([self.ip4_all_nodes_address, self.ip6_all_nodes_address]) else {},
                # ip daddr 224.0.0.1 ip daddr set [IP4_ALL_NODES_ADDRESS]
                {
                    'chain': 'raw-output',
                    'expr': [{'match': {'left': {'payload': {'protocol': 'ip', 'field': 'daddr'}},
                                        'op': '==',
                                        'right': '224.0.0.1'}},
                             {'mangle': {'key': {'payload': {'protocol': 'ip', 'field': 'daddr'}},
                                         'value': str(self.ip4_all_nodes_address)}}],
                } if self.ip4_all_nodes_address is not None else {},
                # ip6 daddr ff02::1 ip6 daddr set [IP6_ALL_NODES_ADDRESS]
                {
                    'chain': 'raw-output',
                    'expr': [{'match': {'left': {'payload': {'protocol': 'ip6', 'field': 'daddr'}},
                                        'op': '==',
                                        'right': 'ff02::1'}},
                             {'mangle': {'key': {'payload': {'protocol': 'ip6', 'field': 'daddr'}},
                                         'value': str(self.ip6_all_nodes_address)}}],
                } if self.ip6_all_nodes_address is not None else {},
                # policy accept
            ],
        }
        obj = NetlinkState.NFTable(family=str(NFProto.INET).lower(), name=self.table_name, spec=nf_table_inet_spec)
        self.nf_table_map[obj.family, obj.name] = NFTable()
        self.add(obj)

    def event_context_factory(self) -> NetlinkEventContext:
        return NetlinkEventContext(manager=self,
                                   active=self.active,
                                   pending_add=self.pending_add,
                                   pending_remove=self.pending_remove,
                                   instance_id=self.instance_id,
                                   nf_table_map=self.nf_table_map,
                                   svi_map=self.svi_map,
                                   table_name=self.table_name,
                                   svi_config=self.svi_config,
                                   default_svi_config=self.default_svi_config)

    def register_svi(self, name: str) -> None:
        try:
            svi = self.svi_map[name]
        except KeyError:
            self.add(NetlinkState.SVI(name=name))
            svi = self.svi_map[name] = NetlinkSVI(refcount=0, name=name)
        svi.refcount += 1

    def unregister_svi(self, name: str) -> None:
        svi = self.svi_map[name]
        svi.refcount -= 1
        if svi.refcount == 0:
            self.remove(NetlinkState.SVI(name=name))

    def reload(self) -> None:
        logging.debug("Reloading netlink state from kernel.")
        self.pending_add.update(self.active)
        self.active.clear()
        self.pending_remove.clear()

        nft = libnftables.Nftables()
        with (IPRouteExtended() as ipr,
              NFTablesRaw() as nft_raw):
            context = NetlinkLoadContext(manager=self,
                                         active=self.active,
                                         pending_add=self.pending_add,
                                         pending_remove=self.pending_remove,
                                         instance_id=self.instance_id,
                                         nf_table_map=self.nf_table_map,
                                         svi_map=self.svi_map,
                                         table_name=self.table_name,
                                         svi_config=self.svi_config,
                                         default_svi_config=self.default_svi_config,
                                         ipr=ipr,
                                         nft=nft,
                                         nft_raw=nft_raw)
            self.reload_objects(context)

        logging.debug("Netlink state: {} active, {} to add, {} to remove.".format(len(self.active), len(self.pending_add), len(self.pending_remove)))

    def commit(self) -> None:
        logging.debug("Committing netlink state to kernel.")
        nft = libnftables.Nftables()
        with (IPRouteExtended() as ipr,
              NFTablesRaw() as nft_raw):
            context = NetlinkOperationContext(manager=self,
                                              instance_id=self.instance_id,
                                              nf_table_map=self.nf_table_map,
                                              svi_map=self.svi_map,
                                              table_name=self.table_name,
                                              svi_config=self.svi_config,
                                              default_svi_config=self.default_svi_config,
                                              ipr=ipr,
                                              nft=nft,
                                              nft_raw=nft_raw)
            self.commit_objects(context)

        logging.debug("Netlink state: {} active, {} to add, {} to remove.".format(len(self.active), len(self.pending_add), len(self.pending_remove)))
