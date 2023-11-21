import logging

from pr2modules.netlink.rtnl.ifinfmsg import protinfo_bridge  # type: ignore # No stubs.
from pr2modules.netlink.rtnl.ndmsg import ndmsg  # type: ignore # No stubs.


# FIXME: this won't be necessary at some point.
protinfo_bridge_map = (('IFLA_BRPORT_UNSPEC', 'none'),
                       ('IFLA_BRPORT_STATE', 'uint8'),
                       ('IFLA_BRPORT_PRIORITY', 'uint16'),
                       ('IFLA_BRPORT_COST', 'uint32'),
                       ('IFLA_BRPORT_MODE', 'uint8'),
                       ('IFLA_BRPORT_GUARD', 'uint8'),
                       ('IFLA_BRPORT_PROTECT', 'uint8'),
                       ('IFLA_BRPORT_FAST_LEAVE', 'uint8'),
                       ('IFLA_BRPORT_LEARNING', 'uint8'),
                       ('IFLA_BRPORT_UNICAST_FLOOD', 'uint8'),
                       ('IFLA_BRPORT_PROXYARP', 'uint8'),
                       ('IFLA_BRPORT_LEARNING_SYNC', 'uint8'),
                       ('IFLA_BRPORT_PROXYARP_WIFI', 'uint8'),
                       ('IFLA_BRPORT_ROOT_ID', 'br_id'),
                       ('IFLA_BRPORT_BRIDGE_ID', 'br_id'),
                       ('IFLA_BRPORT_DESIGNATED_PORT', 'uint16'),
                       ('IFLA_BRPORT_DESIGNATED_COST', 'uint16'),
                       ('IFLA_BRPORT_ID', 'uint16'),
                       ('IFLA_BRPORT_NO', 'uint16'),
                       ('IFLA_BRPORT_TOPOLOGY_CHANGE_ACK', 'uint8'),
                       ('IFLA_BRPORT_CONFIG_PENDING', 'uint8'),
                       ('IFLA_BRPORT_MESSAGE_AGE_TIMER', 'uint64'),
                       ('IFLA_BRPORT_FORWARD_DELAY_TIMER', 'uint64'),
                       ('IFLA_BRPORT_HOLD_TIMER', 'uint64'),
                       ('IFLA_BRPORT_FLUSH', 'flag'),
                       ('IFLA_BRPORT_MULTICAST_ROUTER', 'uint8'),
                       ('IFLA_BRPORT_PAD', 'uint64'),
                       ('IFLA_BRPORT_MCAST_FLOOD', 'uint8'),
                       ('IFLA_BRPORT_MCAST_TO_UCAST', 'uint8'),
                       ('IFLA_BRPORT_VLAN_TUNNEL', 'uint8'),
                       ('IFLA_BRPORT_BCAST_FLOOD', 'uint8'),
                       ('IFLA_BRPORT_GROUP_FWD_MASK', 'none'),
                       ('IFLA_BRPORT_NEIGH_SUPPRESS', 'uint8'),
                       ('IFLA_BRPORT_ISOLATED', 'uint8'))

if len(protinfo_bridge.nla_map) < len(protinfo_bridge_map):
    protinfo_bridge.nla_map = protinfo_bridge_map
else:
    logging.warning("Patch for IFLA_BRPORT_* NLA map no longer required.")

ndmsg_map = (('NDA_UNSPEC', 'none'),
             ('NDA_DST', 'ipaddr'),
             ('NDA_LLADDR', 'lladdr'),
             ('NDA_CACHEINFO', 'cacheinfo'),
             ('NDA_PROBES', 'uint32'),
             ('NDA_VLAN', 'uint16'),
             ('NDA_PORT', 'be16'),
             ('NDA_VNI', 'uint32'),
             ('NDA_IFINDEX', 'uint32'),
             ('NDA_MASTER', 'uint32'),
             ('NDA_LINK_NETNSID', 'none'),
             ('NDA_SRC_VNI', 'none'),
             ('NDA_PROTOCOL', 'uint8'))

if len(ndmsg.nla_map) < len(ndmsg_map):
    ndmsg.nla_map = ndmsg_map
else:
    logging.warning("Patch for NDA_* NLA map no longer required.")
