__all__ = ['lxmesh', 'kernel', 'NFTablesSets']

import enum


class lxmesh(enum.IntEnum):
    RTPROT_LXMESH   = 242


class kernel(enum.IntEnum):
    IN6_ADDR_GEN_MODE_NONE = 1

    NUD_REACHABLE           = 0x02
    NUD_NOARP               = 0x40
    NUD_PERMANENT           = 0x80

    NTF_SELF                = 0x02
    NTF_MASTER              = 0x04
    NTF_EXT_LEARNED         = 0x10

    RT_TABLE_UNSPEC         = 0

    RT_SCOPE_UNIVERSE       = 0
    RT_SCOPE_LINK           = 253
    RT_SCOPE_NOWHERE        = 255

    RTN_UNICAST             = 1

    MDB_TEMPORARY           = 0
    MDB_PERMANENT           = 1

    MDB_FLAGS_OFFLOAD       = (1 << 0)
    MDB_FLAGS_FAST_LEAVE    = (1 << 1)
    MDB_FLAGS_STAR_EXCL     = (1 << 2)
    MDB_FLAGS_BLOCKED       = (1 << 3)


# FIXME: change to StrEnum in Python 3.11.
class NFTablesSets(enum.Enum):
    svis            = 'svis'
    multicast_svis  = 'multicast-svis'
    marks           = 'marks'
    eth_addresses   = 'eth-addresses'
    ip4_addresses   = 'ip4-addresses'
    ip6_addresses   = 'ip6-addresses'
    in_services     = 'in-services'
    out_services    = 'out-services'

    def __str__(self) -> str:
        return self.value
