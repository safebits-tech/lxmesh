import logging

from pr2modules.netlink.rtnl.ndmsg import ndmsg  # type: ignore[import-untyped]


# FIXME: this won't be necessary at some point.
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
