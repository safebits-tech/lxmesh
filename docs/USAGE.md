# LXMesh Usage

LXMesh is a networking control-plane application that facilitates the
implementation of an EVPN architecture to connect LXD system containers running
on supervisor hosts that can communicate over an arbitrary layer-3 network (such
as the Internet).

This document describes how LXMesh operates and how to configure it, as well as
the other software necessary to implement an EVPN architecture. In particular,
configuration examples are provided for:

- systemd-networkd – in order to create and configure network devices;
- FRR – for the EVPN implementation and as BGP route reflectors;
- strongSWAN - for protecting inter-supervisor hosts traffic.

However, LXMesh is designed to be non-opinionated, so any other software can be
used instead of these, as long as they achieve the objective (e.g. ifupdown for
network device creation or a router from Juniper Networks as a route reflector).

You should ensure you have read at least the
[Terminology](/README.md#terminology) section of the top-level README file,
although the entire contents of it provide a useful introduction.

This document is structured as follows:
- [Architecture](#architecture)
- [Configuration and Daemon Management](#configuration-and-daemon-management)
- [Operation](#operation)
- [The Bridge Device](#the-bridge-device)
- [The VXLAN Device](#the-vxlan-device)
- [EVPN Configuration](#evpn-configuration)
- [IPsec Configuration](#ipsec-configuration)
- [Firewall](#firewall)
    - [Route Reflector Firewall](#route-reflector-firewall)
    - [Supervisor Host Firewall](#supervisor-host-firewall)
    - [Reverse Path Filtering](#reverse-path-filtering)
- [Intermission](#intermission)
- [LXD Container Configuration](#lxd-container-configuration)
    - [Address Assignment](#address-assignment)
    - [Address Validation](#address-validation)
    - [MTU](#mtu)
    - [Restricting Container Communication](#restricting-container-communication)
- [Multicast](#multicast)
- [External Networks](#external-networks)
- [Traffic Segregation via VRFs](#traffic-segregation-via-vrfs)

## Architecture

Consider the following network diagram. EVPN technology allows the
implementation of a virtualised layer-2 broadcast domain that spans any number
of supervisor hosts, as long as these have layer-3 connectivity between them.
Additionally, they can automatically discover each other based on Type 3 routes:
each supervisor host only needs to be configured with the addresses of the BGP
route reflectors; this allows simple horizontal scalability without the need to
reconfigure existing supervisor hosts. In fact, this document offers sample
configuration which is identical for all supervisor hosts. Packets exchanged
between containers running on different supervisor hosts are encapsulated using
on-demand tunnels (this document describes the use of VXLAN for this purpose)
and transmitted directly between the respective hosts; this effectively creates
a full mesh of virtual tunnels between all supervisor hosts.

If the containers need to communicate with external networks, each LXD
supervisor host acts as a gateway for forwarding traffic towards those networks;
they are all provisioned with the same IPv4 and IPv6 address, in order to avoid
issues with container migration. In order for external networks to be able to
route traffic destined for a container to the appropriate supervisor host, each
supervisor host can advertise host routes (/32s and /128s for IPv4 and IPv6,
respectively) for each of the containers it manages. If container traffic should
be segragated from other network traffic on the supervisor host, VRFs can be
employed.

IPsec can be used to provide confidentiality and integrity protection to packets
exchanged over the virtual tunnel, as well as to the BGP sessions between the
supervisor hosts and the route reflectors. This also doesn't require each
supervisor host to be configured with the addresses of the other supervisor
hosts, thus not being a hindrance to horizontal scalability.

![LXMesh basic network diagram](/docs/images/lxmesh-full.svg)

Consider the case of the container with the IPv4 address 192.0.2.10 wishing to
communicate with 192.0.2.50 when a simple EVPN architecture is deployed (without
LXMesh). The following steps will take place:

1. Since 192.0.2.10 is configured with the network route 192.0.2.0/24 assigned
   to an interface, it will assume 192.0.2.50 is on the same broadcast domain
   and will need to learn its link-layer (Ethernet) address.
1. In order to do that, it will send an ARP request to the broadcast address
   ff:ff:ff:ff:ff:ff. In normal EVPN operation, this needs to be broadcasted to
   all other local containers, as well as all learned VTEPs – all discovered
   supervisor hosts; these in turn will need to flood all of their containers.
   The frame is encapsulated using a tunneling technology such as VXLAN and the
   packet is either replicated at the source for each of the possible VTEP
   destinations (source-based replication), or is sent out using multicast if
   the underlay network supports it. This process is called broadcast flooding.
1. This ARP request will have 192.0.2.10's link-layer address as a source (let's
   say 00:53:00:10:10:10); upon forwarding of the frame, the managing supervisor
   host will learn that 00:53:00:10:10:10 is local, so it will install it in its
   forwarding table and advertise it, via the route reflectors, to all other
   supervisor hosts as a Type 2 route.
1. When 192.0.2.50 receives the ARP request, it will generate an ARP reply
   destined for 00:53:00:10:10:10, with its own link-layer address as a source
   (let's say 00:53:00:50:50:50).
1. When 192.0.2.50's supervisor host receives the ARP reply, if it had already
   learned via BGP that 00:53:00:10:10:10 is hosted on a specific supervisor
   host, it can encapsulate the frame and send it straight to that supervisor
   host only. However, the BGP update may not have had time to propagate yet, in
   which case the only option is to again flood all VTEPs using source-based
   replication or multicast if the underlay supports it. The other supervisor
   hosts which don't manage 192.0.2.10 may also not have received or processed
   the 00:53:00:10:10:10 BGP update, in which case they'll have no other option
   but to flood all of their respective containers with the ARP reply. This
   process is called unknown unicast flooding.
1. 192.0.2.50's supervisor host will learn from the ARP reply that
   00:53:00:50:50:50 is local to it, so it will install it in its forwarding
   table and advertise it, via the BGP route reflectors, to all other supervisor
   hosts as a Type 2 route.
1. When the ARP reply reaches 192.0.2.10's supervisor host, it will use its
   forwarding table entry to direct it towards the 192.0.2.10 container (its
   unlikely at this stage that the forwarding table entry will not have been
   installed or will have expired).
1. 192.0.2.10 finally has 192.0.2.50's link-layer address, so it can send a
   unicast datagram towards it (e.g. containing a TCP SYN packet). If the
   former's supervisor host did not yet receive or process the earlier BGP
   update for 00:53:00:50:50:50, it will also have to treat this frame as
   unknown unicast and forward it to all other supervisor hosts.
1. If 192.0.2.50 wishes to reply to 192.0.2.10, the same process is likely to
   occur, with the only difference that the ARP reply from 192.0.2.10 to
   192.0.2.50 is very likely to not require flooding as unknown unicast, thus a
   bit more efficient.
1. Very shortly, though, the entire network will have learned of the two
   link-layer addresses, 00:53:00:10:10:10 and 00:53:00:50:50:50, and
   communication between the two containers can take place efficiently.
1. Once communication between the two containers stops, the two link-layer
   addresses will expire from the forwarding tables of their respective
   supervisor hosts, triggering a BGP update so that the rest of the network can
   forget about them. The entire process may then repeat at a later date.

For IPv6, the process is quite similar, with the following differences:

1. IPv6 uses multicast for neighbour discovery, so each supervisor host should
   be properly configured to have a querier on the local bridge and to implement
   snooping, but to not forward the MLD queries to other supervisor hosts over
   tunnels.
1. Each container will automatically join the solicited-node multicast group for
   its respective address: 2001:db8::10 will join ff02::1:ff00:10 and
   2001:db8::50 will join ff02::1::ff00:50.
1. Without support for RFC9251 in the EVPN implementation and the kernel tunnel
   driver, the MLD reports can be flooded to all VTEPs. This way, each
   supervisor host knows that a group is joined by a container on another
   supervisor host.
1. 2001:db8::10 will send a neighbour discovery solicitation to
   ff02::1::ff00:50, with a destination link-layer address of 33:33:ff:00:00:50.
   In the current implementation of VXLAN in the Linux kernel, even if a
   multicast forwarding entry for this group is learned on the VXLAN interface
   (from receipt of MLD reports), the packet is still source-replicated to all
   known VTEPs; as an alternative, if the underlay network supports multicast,
   the encapsulated packet can use a point-to-multipoint path. Either way, the
   neighbour discovery solicitation ends up on all supervisor hosts, but, due to
   snooping functionality, it will not be flooded to any containers; only
   2001:db8::50 will receive it.
1. The neighbour discovery advertisement will be forwarded in exactly the same
   way as the ARP reply, including the risk of unknown unicast flooding.

On a large deployment with very dynamic container communication, the number of
flooded frames and BGP updates can grow significantly. Additionally, when a
container is migrated from one supervisor host to another, the retraction of the
link-layer address advertisement (EVPN Type 2 route) from the old supervisor
host may be delayed, impeding communication for a short duration.

By contrast, LXMesh takes advantage of the fact that BGP was designed to be able
to handle a very large number of routes (after all, the IPv4 global routing
table is approaching one million entries and we're still fine). Additionally,
each supervisor host knows what containers it is managing and their link-layer
and network-layer addresses. The main function of LXMesh is to continuously
monitor LXD using its REST API (including via the websockets event endpoint, in
order to quickly react to events), determine if it is supposed to manage a
container's network device and insert static bridge forwarding entries and
ARP/NDP entries into the local kernel using Netlink. These are then picked up by
an EVPN implementation (such as FRR) and distributed to all other supervisor
hosts. Therefore, as long as a container is running, whether it is communicating
with other entities or not, all supervisor hosts within the entire network are
aware of its link-layer and network-layer (IPv4 and IPv6) addresses. BGP updates
are effectively only generated when a container goes through a lifecycle event
(e.g. it is stopped, started, paused, unpaused) or its LXD network configuration
is changed (e.g. by an administrator of the supervisor host). This results in a
relatively static BGP state and it means that unknown unicast flooding never
needs to take place. This setup is perfectly standards compliant, as the EVPN
reference describes that link-layer and network-layer addresses can be learned
either through the typical bridge inspection and ARP/NDP processes or through
any other control-plane application. LXMesh is effectively such a control-plane
application and should be compatible with any standards-compliant EVPN
implementation (it has been tested with FRR).

Furthermore, through the use of the neigh\_suppress and proxyarp bridge port
settings, the supervisor host generates ARP replies and NDP advertisements on
behalf of the recipient. This completely eliminates the need to flood ARP
requests and NDP solicitations. Please note that these correspond to the
IFLA\_BRPORT\_NEIGH\_SUPPRESS and IFLA\_BRPORT\_PROXYARP Netlink attributes and
the latter has nothing to do with the similarly named per-interface proxy\_arp
setting (e.g. /proc/sys/net/ipv4/conf/all/proxy\_arp). This is a rather
underdocumented feature of the Linux kernel (see the
[bridge(8)](https://manpages.debian.org/unstable/iproute2/bridge.8.en.html)
manual page); given the naming, it seems to be implemented for EVPN.

LXMesh performs a number of other functions:
- It configures the bridge devices, the VXLAN devices and the containers'
  corresponding veth devices with appropriate (secure-by-default) settings.
  These aren't strictly necessary for the system to function, but provided as a
  convenience.
- Disables broadcasting altogether (multicast can be used instead, if necessary)
  between containers, but only on the devices managed by LXMesh, of course.
- It configures a stateful firewall using nftables to:
    - enforce validation of link-layer and network-layer addresses for packets
      originating from containers;
    - ensure ARP, ICMP, IGMP and ICMPv6 packets from containers do not affect
      security and are only forwarded where appropriate;
    - restrict traffic to and from containers using a default-deny policy;
      allowed services have to be defined per LXD container configuration
      (profiles can also be used, of course);
    - applies a netfilter mark for traffic originating from containers using
      custom-named tags; the low-order 16 bits of the netfilter mark can be
      carried from one supervisor host to another using VXLAN's GBP extension,
      potentially allowing firewall rules to be written in a friendly fashion
      without the need for addresses (but see current limitations described in
      the [VXLAN Device](#the-vxlan-device) section below).
- Optionally starts and supervises a dnsmasq process to provide DHCPv4 and
  DHCPv6 services to the containers. The default configurations provided
  disables all other dnsmasq services, but this can be easily customised. The
  dnsmasq instance managed by LXMesh will not conflict with any other dnsmasq
  instance ran on the same supervisor host (including dnsmasq managed by LXD),
  as it is by default restricted to the bridge devices explicitely configured to
  be managed by LXMesh (and, since by default there aren't any, dnsmasq would
  not even be started).
- Optionally inserts host routes (/32s and /128s for IPv4 and IPv6,
  respectively) for local containers in a configurable routing table, so that
  these can then be advertised by a BGP daemon (such as FRR) to external
  networks. This allows external networks to route traffic destined for a
  container to the appropriate supervisor host.

LXMesh will not interfere with any other software or configuration on the
supervisor hosts on which it is installed (but with two exceptions, described
here and prominently displayed as a warning in the installation documentation):
- It doesn't modify LXD containers and ignores those which aren't explicitely
  configured to be managed by LXMesh. For LXD containers explicitely configured
  to be managed by LXMesh, it will write a one-time configurable attribute to
  store a persistent identifier, in the form of a UUID. The reason for doing
  this is described in this document.
- Only modifies bridge devices, VXLAN devices and container's veth devices if
  these are explicitly configured to be managed by LXMesh. In fact, a container
  can be connected to other LXD networks at the same time as to a bridge managed
  by LXMesh.
- Sets up the nftables rules in separate tables (with configurable names) and
  all their chains are designed to not affect traffic that is not explicitly
  configured to be managed by LXMesh. This means that the system integrator is
  free to describe firewall rules using any other iptables or nftables-based
  system without any sort of conflict. LXMesh nftables rules need not be
  integrated into the existing firewall configuration, but there is no issue if
  they are either (e.g. by saving the entire nftables ruleset, including
  LXMesh's tables, and restoring it). There are, however, two issues (the two
  exceptions described earlier):
    - Because LXMesh sets up a nftables table in the bridge family, ebtables
      will refuse to work. Migrating from ebtables to nftables solves this
      problem.
    - Because LXMesh bridge family rules make use of conntrack, the
      nf\_conntrack\_bridge module is automatically loaded. This causes
      conntrack lookups for packets entering a bridge device to be performed at
      an earlier netfilter hook, which means that the `notrack` nftables
      statement or the `NOTRACK` iptables action at the raw priority of the
      inet/ip/ip6 family prerouting hooks are effectively too late and no longer
      do anything. This does not affect packets entering non-bridge devices or
      the output hook. Unfortunately, there is no way for LXMesh to avoid this,
      unless nftables implements some sort of _delay-conntrack-lookup_
      statement. This is only an issue if you make use of the `notrack`
      statement or `NOTRACK` action for packets entering via a bridge device.

## Configuration and Daemon Management

The rest of this documentation is organised as a step-by-step tutorial to
understanding the system and configuring LXMesh and other software necessary to
implement the architecture described above. The LXMesh software and its
dependencies should already be installed, as per the instructions in the
[docs/INSTALL.md](/docs/INSTALL.md) file.

LXMesh is configurable using a configuration file in the YAML format (for
consistency with LXD). The path to this file must be passed to the daemon using
a command-line argument. The configuration file is meant to have
security-sensible default values.

The Ubuntu package described in the installation page sets up a default
configuration file at `/etc/lxmesh/agent.yaml`. This file contains all possible
configuration options, but most are commented out, with the associated default
value represented. The ones which are not commented out contain sensible
defaults (such as starting dnsmasq with useful arguments).

The Ubuntu package also contains a configuration directory for dnsmasq at
`/etc/lxmesh/dnsmasq.d`, with a single file containing sensible defaults for
dnsmasq (e.g. disables all other functionality apart from DHCPv4 and DHCPv6).
You can customise the behaviour of the LXMesh-managed dnsmasq instance by either
modifying this file or dropping other files in this directory. The directory is
simply referenced by the default arguments for dnsmasq in the LXMesh
configuration (see `dhcp.server.arguments`); modifying those could be used to
stop this directory from being read by dnsmasq.

Finally, the Ubuntu package also provides a SystemD unit file to start the
LXMesh daemon, called `lxmesh-agent`. This executes the daemon with as few
privileges as possible (uses a dynamic user assigned to the `lxd` supplementary
group and sets only the required capabilities), sets up a restricted environment
using bind mounts and restricts the available system calls.

The LXMesh Agent daemon is meant to be robust across restarts or crashes: upon
starting up, it will only modify Netlink objects if they are different from the
desired state. Netlink objects are not affected by the LXMesh Agent stopping.
This effectively makes it safe to restart the daemon without affecting the LXD
containers or their network connectivity in any way (apart from the fact that
dnsmasq also restarts, but DHCP implementations should be robust anyway).
Therefore, functionality to reload the configuration file is not implemented and
a restart of the daemon is necessary if a configuration change is to be applied.
This can be performed using:

```sh
$ sudo systemctl restart lxmesh-agent
```

The daemon logs straight to the SystemD journal or to stdout, depending on
whether the `--systemd` argument is specified on the command-line (this is
included by default in the packaged unit file). The log level can be controlled
through the `general.log-level` configuration option, which takes a value of
`debug`, `info`, `warning`, `error` or `critical`.

The LXMesh Agent does not need to keep any persistent state. If configured to,
via the `dhcp.config-file` and `dhcp.hosts-file` configuration file options, it
will write DHCP config files in the format expected by dnsmasq; the paths are
interpreted as relative to `/var/lib/lxmesh`. The files are replaced atomically,
so they would never get corrupted or incomplete if a crash occurs. If these
options aren't set, the daemon doesn't write to the filesystem at all.

The `CAP_NET_ADMIN` capability is required in order to manage kernel networking
configuration via Netlink. The `CAP_NET_BIND_SERVICE` and `CAP_NET_RAW`
capabilities are additionally required by dnsmasq, so they are dropped from the
effective set and only retained in the inheritable set if the LXMesh daemon is
configured to start a DHCP server, via the `dhcp.server.executable`
configuration setting (otherwise, they are also dropped from the permitted set).
Any other capabilities available at start-up time are dropped. The packaged
SystemD unit file only configures these three.

The DHCP daemon is executed in the same environment as the LXMesh Agent. The
dnsmasq build in Ubuntu, as provided by the dnsmasq-base package, is hardcoded
to write DHCP lease files to `/var/lib/misc`. This directory is bind-mounted in
the provided SystemD unit file to `/var/lib/lxmesh`, so that dnsmasq stores its
state is this latter directory and avoids conflicts with any other instance
running on the same host. More information about how the spawned DHCP server
process is managed is provided in the [Address Assignment](#address-assignment)
section, below.

## Operation

This section describes the general principles of how LXMesh operates. The
level of detail here is meant to assist in debugging issues with its
functionality.

The core functionality of the LXMesh Agent is implemented by keeping an
in-memory view of current state and synchronising it with external systems.
There are three such state views, with the synchronisation occuring in different
directions:

- **LXD Containers**: LXMesh keeps information about the containers and their
  network devices that it is interested in. It obtains this information using
  the LXD REST API, by accessing the local LXD UNIX socket (which by default is
  `/var/snap/lxd/common/lxd/unix.socket`). The SystemD unit file adds the `lxd`
  supplementary group to the process in order for it to have permissions to
  access this socket. The LXD daemon is considered to hold the authoritative
  data, so the in-memory state held by LXMesh is synchronised to match what the
  LXD daemon reports.
- **Netlink State**: This covers a number of different objects which are all
  managed through the Netlink interface: nftables objects, network devices,
  network addresses, network routes, ARP/NDP entries, bridge forwarding table
  entries, bridge multicast forwarding table entries. Most of these are
  synchronised from the LXMesh daemon to the Linux kernel: LXMesh keeps a view
  of the desired state and performs operations so that the kernel objects match
  that desired state. There are a few bits of information that are synchronised
  in the opposite direction as well, such as the routing table corresponding to
  a particular network device or the VXLAN interfaces associated with bridge
  interfaces.
- **DHCP State**: This covers the information necessary to set up the
  configuration files for the supervised DHCP server. Some information is
  retrieved from the Linux kernel (such as addresses assigned to SVIs) and some
  information is written to the filesystem (the DHCP configuration and hosts
  files).

The state synchronisation algorithms for these three subsystems are quite
similar. LXMesh performs a periodic full information fetch to determine the
state of the external systems. If the synchronisation direction of a state
object is from an external system to LXMesh, then the full fetch causes the
internal state to be updated to reflect the actual state (for example, what LXD
containers are currently running and their configuration). If the synchronisation
direction of a state object is in the opposite direction, from LXMesh towards
the external system, then LXMesh will compare the actual state that was just
retrieved with its own view of the desired state, determine what operations are
necessary to take the actual state to the desired state and performs only those
operations. Therefore, the full periodic information fetch does not cause LXMesh
to take any actions unless these are necessary.

Additionally, LXMesh registers to receive events whenever the external systems'
states change, so that it can react in near-real-time to these changes. For the
LXD state, it uses the websockets events API endpoints, while for kernel objects
it uses the Netlink multicast group subscription feature. This means that LXMesh
can react instantaneously to operations and ensure container connectivty to set
up appropriately. For example, if a system administrator manually removes a
route entry that was set up by LXMesh, it will be immediately recreated. If a
container's configuration is modified (e.g. by using `lxc config set`), LXMesh
will react without delay.

The event handling algorithm means that the periodic full information fetch
should actually not change any state, because LXMesh should already be
synchronised with the external systems' states and the other way around.
However, there are two aspects here:
1. Resources are finite. Both the LXD events websocket and the Netlink multicast
   subscription socket have limits on the buffer sizes. That means that there is
   a possibility that LXMesh could miss an event, if it could not keep up with
   the external system.
1. There is always the possibility that a bug, either in LXMesh or in the
   external systems, causes LXMesh to believe that the states are synchronised,
   when in reality they aren't.

Therefore, the periodic full information fetch provides robustness to the
system, with the interval between fetches being a compromise between stability
and resource usage (the intervals are configurable).

Finally, if LXMesh fails to perform the operations necessary to take the actual
state to the desired state, it will continuously retry at short fixed intervals,
without ever giving up. However, the next scheduled full information fetch is
still executed, which will cause a recomputation of the list of operations
necessary to be performed to reach the desired state.

The following set of configuration options are relevant to this operation:
- **lxd.initial-reload-interval** (defaults to 10 seconds): since the entire
  functionality of LXMesh depends on knowing the LXD containers' state, a fetch
  of that information is the first thing that takes place; if that fetch fails,
  this is retried periodically at this interval.
- **lxd.reload-interval** (defaults to 60 seconds): this is the interval at
  which periodic fetches of all LXD containers' state are performed; also, see
  the **lxd.reload-jitter** setting below.
- **lxd.reload-jitter** (defaults to 5 seconds): in order to avoid the various
  periodic information fetches from being scheduled at the same time, a
  uniformly random amount of time is added/subtracted from the reload interval;
  therefore, after a full information fetch, the next one will actually be
  scheduled at **lxd.reload-interval** +/- **lxd.reload-jitter**, with the value
  chosen using a uniformly-distributed random function within these limits.
- **dhcp.reload-interval** (defaults to 60 seconds): this is the interval at
  which periodic fetches of information relevant for DHCP configuration are
  executed (e.g. addresses assigned to bridge network devices); also, see the
  **dhcp.reload-jitter** setting below.
- **dhcp.reload-jitter** (defaults to 5 seconds): in order to avoid the various
  periodic information fetches from being scheduled at the same time, a
  uniformly random amount of time is added/subtracted from the reload interval;
  therefore, after a full information fetch, the next one will actually be
  scheduled at **dhcp.reload-interval** +/- **dhcp.reload-jitter**, with the
  value chosen using a uniformly-distributed random function within these
  limits.
- **dhcp.retry-interval** (defaults ot 10 seconds): if the DHCP state cannot be
  comitted (the configuration files written), then the operations are retried
  continuously at this interval.
- **netlink.reload-interval** (defaults to 60 seconds): this is the interval at
  which periodic fetches of all networking kernel objects are performed using
  Netlink; most of these are managed by LXMesh, so they translate to an actual
  state which is then compared to the desired state.
- **netlink.reload-jitter** (defaults to 5 seconds): in order to avoid the
  various periodic information fetches from being scheduled at the same time, a
  uniformly random amount of time is added/subtracted from the reload interval;
  therefore, after a full information fetch, the next one will actually be
  scheduled at **netlink.reload-interval** +/- **netlink.reload-jitter**, with
  the value chosen using a uniformly-distributed random function within these
  limits.
- **netlink.retry-interval** (defaults to 10 seconds): if the Netlink state
  cannot be comitted (the Netlink commands that modify objects fail), then the
  operations are retried continuously at this interval, until they succeed. The
  batch of operations necessary to take the actual state to the desired state is
  executed as a whole; the operations which succeed are removed from the batch
  and if the remaining batch is non-empty, it will be tried again after this
  amount of time. If the failures are actually caused by an incorrect view of
  what the actual state is, then the next full information fetch (as dictated by
  the **netlink.reload-interval** setting) will fix this view and the operations
  batch is recomputed.

Detailed information about the state representation and any performed operations
is logged at the `debug` level (disabled by default). At the default `info`
level, a periodic information reload that does not cause any state
synchronisation operations to be performed (as is expected, if all events were
previously processed) will not generate any log messages.

## The Bridge Device

In order to make use of LXMesh, one or more bridge device must be set up on each
supervisor host. LXMesh can handle as many independent bridge devices as desired
and containers can be assigned to any number of them. The terminology used by
LXMesh is **SVI** (Switch Virtual Interface), as these generally need to be
bridge devices with IPv4 and/or IPv6 addresses assigned to them on the
supervisor host. It is possible to not have any IP addresses assigned to a
bridge device, in which case the containers will not be able to communicate with
external networks and the DHCPv4, DHCPv6 and IPv6 router advertisement features
will not work (the containers would have to be statically configured with their
network settings). This document will cover a setup using a single bridge device
with both IPv4 and IPv6 addresses, as per the earlier diagram.

Settings related to SVIs are configured within the **svi** section of the LXMesh
Agent configuration file. This is a list of objects, with each object referring
to a particular bridge device by its name. Default settings applicable to all
SVIs can be configured with an object without the `name` property. For example,
take the following configuration:

```yaml
svi:
  - netfilter-mark:       0x3
    host-routes:          yes
    # host-routes-table:  unspec
    # multicast:          off
  - name:                 vpc-1
    # netfilter-mark:     0
    host-routes:          no
    # host-routes-table:  unspec
    # multicast:          off
```

Notice that some of the settings are commented-out. The first object does not
specify the `name` property, so acts as default settings for all SVIs, even
those not explicitly configured. If the supervisor host has two SVIs, named
`vpc-1` and `vpc-2`, then the following will happen:

- For `vpc-1`, the `netfilter-mark` setting will be `0x3`, because it is
  inherited from the default section.
- For `vpc-1`, the `host-routes` setting will be `no`, because the `yes` value
  configured in the default section is overwritten.
- For `vpc-1`, all other settings are the LXMesh default ones, because they are
  not specified in either the default section or the SVIs specific section.
- For `vpc-2`, the `netfilter-mark` and `host-routes` settings are inherited
  from the default section, as `0x3` and `yes`, respectively.
- For `vpc-2`, all other settings are the LXMesh default ones, because they are
  not specified in the default section and there is no section with this SVI's
  name.

LXMesh does not create bridge devices. These can be created using any
configuration manager already in use on the system. LXMesh will also not
interact with a bridge device, even if its name is included in the configuration
file, unless LXD containers are associated to it via their configuration (see
section [LXD Container Configuration](#lxd-container-configuration), below).

We'll configure a bridge device called `svi-vpc` using systemd-networkd. The
only requirement is that it is a non-VLAN-aware bridge.


```ini
# /etc/systemd/network/20-svi-vpc.netdev
[NetDev]
Name=svi-vpc
Kind=bridge
MACAddress=00:53:00:01:01:01

[Bridge]
STP=no
ForwardDelaySec=0
```

```ini
# /etc/systemd/network/30-svi-vpc.network
[Match]
Name=svi-vpc
Type=bridge

[Link]
RequiredForOnline=no-carrier

[Network]
ConfigureWithoutCarrier=yes
IgnoreCarrierLoss=yes

LinkLocalAddressing=ipv6
IPv6LinkLocalAddressGenerationMode=eui64

Address=192.0.2.1/24
Address=2001:db8::1/64
IPv6SendRA=yes
IPv6AcceptRA=no
IPv6PrivacyExtensions=no
IPv6DuplicateAddressDetection=0

[IPv6SendRA]
Managed=yes
OtherInformation=yes
RouterLifetimeSec=3600
EmitDNS=no
EmitDomains=no

[IPv6Prefix]
OnLink=yes
AddressAutoconfiguration=no
Prefix=2001:db8::/64
ValidLifetimeSec=3600
PreferredLifetimeSec=3600
```

STP is disabled because it generally doesn't make sense in this kind of
architecture; however, if the bridge is connected to other network devices apart
from the containers' and the VXLAN device, it could still be relevant (LXMesh
doesn't mind). The virtual gateway IPv4 and IPv6 addresses are configured and
should be identical on all supervisor hosts (in order to facilitate migration
and simple management). networkd's RA functionality is enabled, advertising the
IPv6 prefix and that address auto-configuration should not be used, but rather
to have containers request an address via DHCPv6. As an alternative, dnsmasq
could be configured to send router advertisements.

One important aspect is the link-layer address configuration for the bridge
device (the `MACAddress` key in the `/etc/systemd/network/20-svi-vpc.netdev`
file). This could be left out, in which case each supervisor host will generate
its own link-layer address (by default, this is done based on the machine ID, so
it will be very likely different on each of them). There are two possible
problems with this approach:
1. An LXD container will be able to tell that they're running on a specific
   supervisor host or migrated based on the link-layer address that their
   gateway advertises.
1. After a migration, an LXD container may retain the ARP/NDP cache entry with
   the old supervisor host's link-layer address, which may cause initial
   connectivity issues.

The safest approach is to generate a random MAC address and assign it to all
supervisor hosts (as shown above).

If LXMesh is going to interact with a bridge device because it is referenced by
an LXD container's configuration, then it will enforce the following bridge
settings on it:
- **IFLA_BR_MCAST_ROUTER**: 2 – this is necessary to work around a Linux kernel
  bug for bridge devices that are associated to a VRF and which act as the local
  multicast querier.
- **IFLA_BR_MCAST_SNOOPING**: enabled – LXMesh enforces a correct multicast
  configuration, so multicast snooping will ensure efficient multicast
  forwarding.
- **IFLA_BR_MCAST_QUERIER**: enabled – for multicast to work correctly, at least
  one querier is required on each broadcast domain, so this makes the supervisor
  host one. A different querier could exist, too, but not on one of the
  containers, because the LXMesh nftables rules block IGMP and MLD queries from
  them.
- **IFLA_BR_MCAST_IGMP_VERSION**: 3 – there would technically not be a problem
  with the default value of 2, but the newest version (which is from 2002) is
  enforced for consistency with the MLD version.
- **IFLA_BR_MCAST_MLD_VERSION**: 2 – the default version of 1 would cause
  issues, as reports are sent to a multitude of destination addresses, rather
  than the much simpler and single ff02::16 all MLDv2-capable routers address in
  use by MLDv2 (which is a protocol from 2004). See the [Multicast](#multicast)
  section below for more information.

Once the systemd-networkd configuration files are all set, the bridge device
will be created by executing the following command (or if systemd-networkd is
restarted, for example, because of a reboot):

```sh
$ sudo networkctl reload
```

## The VXLAN Device

The EVPN architecture requires the use of tunnels to forward frames between the
supervisor nodes. These take the role of PE (Provider Edge) nodes within the
EVPN design. Various tunnelling technologies can be used (MPLS, VXLAN, Geneve),
but FRR only supports VXLAN, so this will be used in this documentation. That
being said, LXMesh is non-opinionated, so if support for other tunneling
technology is available, it will work just fine.

The following systemd-networkd files will create the necessary VXLAN tunnel
device, which we'll name `vxlan-vpc`, and associate it to the earlier-created
bridge device:

```ini
# /etc/systemd/network/20-vxlan-vpc.netdev
[NetDev]
Name=vxlan-vpc
Kind=vxlan
MTUBytes=1450

[VXLAN]
VNI=100
TTL=255
MacLearning=no
DestinationPort=4789
PortRange=4789-4805
Independent=yes
GroupPolicyExtension=yes
```

```ini
# /etc/systemd/network/30-vxlan-vpc.network
[Match]
Name=vxlan-vpc
Type=vxlan

[Link]
RequiredForOnline=no-carrier

[Network]
Bridge=svi-vpc
EmitLLDP=no
IPv6AcceptRA=no
LinkLocalAddressing=no

[Bridge]
NeighborSuppression=yes
Learning=no
UnicastFlood=no
MulticastFlood=no
MulticastRouter=no
```

There are several important aspects to note here:
- A unique VNI must be chosen for each associated SVI and this must be identical
  on all supervisor hosts; the address space for this is 24 bits and you can use
  any value between 1 and 16777214 (0 and 16777215 are reserved).
- The MTU value is quite important to avoid unnecessary fragmentation and, on
  Linux, this will be inherited by the bridge device to which the VXLAN device
  is added (`svi-vpc`). The exact value you need to use depends on what the
  underlay network supports and encapsulation options, including whether IPsec
  is in use or not. The 1450 value is appropriate for VXLAN if IPsec is _NOT_
  used and the underlay network supports a MTU of 1500 (which is pretty
  typical). A more comprehensive discussion of this topic is covered in the
  [MTU](#mtu) section, below.
- The destination port used is 4789 (VXLAN uses UDP and this is the standard
  IANA port). It must be the same on all supervisor hosts. It can also be the
  same on as many VXLAN devices for as many SVIs as you want, but note the
  restriction mentioned below about the GBP extension.
- The source port range is set to 4789 to 4805, which corresponds to 16 ports
  (the start is inclusive and the end is exclusive). The source port for each
  encapsulated frame will be determined using a hash function applied to the
  layer-3 and layer-4 addressing information in the inner frame. This ensures
  that if any equal-cost load balancing is performed within the underlay
  network, frames belonging to the same logical flow are likely to take the same
  path, thus avoiding packet re-ordering. If too small of a range is used, the
  tunnelled packets between supervisor hosts may not be able to take full
  advantage of the bandwidth provided by any equal-cost load balancing performed
  in the underlay. The only downside to a large range is that, if connection
  tracking for VXLAN is not disabled on the supervisor hosts, outgoing packets
  will create conntrack entries for no good reason. This topic is also covered
  in the [Supervisor Host Firewall](#supervisor-host-firewall) section, below.
- The `GroupPolicyExtension` key is set to `yes`, so that the low-order 16 bits
  of the netfilter packet mark can be transported between supervisor hosts and
  used for advanced firewalls; this is also called the GBP (Group-Based Policy)
  extension. You can disable it if it is not of interest and it should not be
  used if IPsec is not employed. Note that if you have multiple VXLAN devices on
  a supervisor host that share the same destination port (4789 above), then they
  must all have the same GBP configuration (either on or off). This is an
  undocumented limitation of the Linux kernel and will result in unexpected
  errors.
- No addresses are configured and, in particular, IPv6 link-local address
  generation is disabled (the kernel's default is to have that enabled).
- Quite important are the `MacLearning`, `NeighborSuppression` and `Learning`
  keys. These are required for the EVPN configuration.
- The `*Flood` keys and `MulticastRouter` key ensure that flooding does not take
  place unnecessarily from one supervisor host to all other supervisor hosts.
  There is another bridge port setting, to control broadcast flooding, which is
  not configurable through systemd-networkd at the time of this writing. It can
  be set via udev, if necessary, but note the comment below about LXMesh
  enforcing some bridge port attributes.

LXMesh will detect VXLAN devices associated to SVI bridge devices that it is
interested in. It will enforce the following set of attributes for them (the
names are the Netlink attributes):
- **IFLA_BRPORT_LEARNING**: disabled – addresses reachable via the tunnel should
  be exclusively learned via BGP in an EVPN configuration. Corresponds to the
  `Bridge.Learning` systemd-networkd key.
- **IFLA_BRPORT_UNICAST_FLOOD**: disabled – LXMesh ensures that the entire
  network is aware of all the containers on all supervisor hosts, so that
  flooding of unknown unicast traffic becomes unnecessary; this would have to be
  enabled in a normal EVPN configuration, without LXMesh. Corresponds to the
  `Bridge.UnicastFlood` systemd-networkd key.
- **IFLA_BRPORT_PROXYARP**: disabled – this is rather redundant, as it is not
  only the default value, but the nftables rules ensure that ARP packets do not
  travel over tunnels. It is only enforced for consistency with the other bridge
  ports that LXMesh manages.
- **IFLA_BRPORT_GUARD**: enabled - STP has no use (and can be dangerous) in an
  EVPN configuration.
- **IFLA_BRPORT_MULTICAST_ROUTER**: disabled – a multicast router port will have
  all multicast traffic flooded through it, indiscriminately, which is rather
  undesirable.
- **IFLA_BRPORT_MCAST_FLOOD**: enabled or disabled, depending on the
  `svi.multicast` configuration setting for the associated SVI. This actually
  works rather differently for VXLAN than for other bridge port types and will
  not cause unknown multicast in a snooping bridge to be flooded, but is
  necessary if multicast traffic is to be sent over tunnels.
- **IFLA_BRPORT_BCAST_FLOOD**: disabled – LXMesh explicitely restricts the
  ability to use broadcast, by design, as documented in the [Topology and
  Requirements
  Specification](/README.md#topology-and-requirements-specification) section of
  the README file.
- **IFLA_BRPORT_NEIGH_SUPPRESS**: enabled – this is required so that the Linux
  kernel answers ARP and NDP queries on behalf of containers hosted on other
  supervisor hosts and for which link-layer and network-layer addresses have
  been learned (which is always the case with LXMesh).
- **IFLA_BRPORT_ISOLATED**: disabled – rather redundant, but included for
  consistency.

On the assumption that the supervisor hosts have a firewall with a default-deny
policy, tunnelled traffic will not be allowed until appropriate rules are set
up. This is covered in the [Supervisor Host Firewall](#supervisor-host-firewall)
section, below.

Once the systemd-networkd configuration files are all set, the VXLAN device will
be created by executing the following command (or if systemd-networkd is
restarted, for example, because of a reboot):

```sh
$ sudo networkctl reload
```

## EVPN Configuration

With the bridge and VLAN devices created, now is a good time to configure the
EVPN implementation. This document contains instructions for using FRR, both on
the supervisor hosts, as well as on route reflectors. In fact, there is nothing
stopping one from using a fixed subset of supervisor hosts as route reflectors
as well, if separate network elements are not desired – it just means that those
particular supervisor hosts which are also route reflectors need to remain
contactable (with split-brain scenarios working as expected).

You should choose a number of route reflectors according to your resiliency
requirements. As long as two supervisor hosts can communicate with the same
route reflector, containers hosted on each of them will be able to communicate
with each other. The route reflectors configuration will be (almost) identical
and they must support reflection of routes with the L2VPN AFI (25) and EVPN SAFI
(70).

The following FRR configuration uses iBGP throughout, with an AS number of
64500, but any BGP configuration that allows the EVPN MP-BGP routes to be
distributed between supervisor hosts will work just fine.

The route reflectors can be configured as follows (the example is for
203.0.113.100, as it needs to reference all _other_ route reflectors):

```
# /etc/frr/frr.conf
frr version 9.0.1
frr defaults traditional
log syslog informational
service integrated-vtysh-config
!
router bgp 64500
 bgp router-id 203.0.113.100
 no bgp default ipv4-unicast
 bgp cluster-id 10.0.0.0
 neighbor supervisors peer-group
 neighbor supervisors remote-as internal
 neighbor supervisors passive
 neighbor reflectors peer-group
 neighbor reflectors remote-as internal
 neighbor 203.0.113.1 peer-group supervisors
 neighbor 203.0.113.2 peer-group supervisors
 neighbor 198.51.100.1 peer-group supervisors
 neighbor 198.51.100.200 peer-group reflectors
 !
 address-family l2vpn evpn
  neighbor supervisors activate
  neighbor supervisors route-reflector-client
  neighbor reflectors activate
 exit-address-family
exit
!
ip nht resolve-via-default
!
ipv6 nht resolve-via-default
!
```

For any other route reflector, just change the `bgp router-id` and membership to
the `reflectors` peer group; the former is technically unnecessary, as a local
IP address would be chosen by FRR anyway and is only included here for clarity.
Notice that this configuration lists all the supervisors' IP addresses, which
means that having many route reflectors, while good for resiliency, is going to
increase the cost when horizontally scaling the supervisors (because each route
reflector would have to be reconfigured). It is also possible to configure
network ranges to allow any supervisor address within them to establish BGP
sessions to the route reflectors (or even a catch-all 0.0.0.0/0). The approach
taken should consider change management policies, security policies (including
authentication requirements, which aren't covered in this example) and any other
organisational requirements. Note that the `bgp cluster-id` configuration
should be identical on all route reflectors.

The base FRR configuration for the supervisors hosts is even simpler and in
this case it can be completely identical on all of them:

```
# /etc/frr/frr.conf
frr version 9.0.1
frr defaults traditional
log syslog informational
service integrated-vtysh-config
!
router bgp 64500
 no bgp default ipv4-unicast
 neighbor reflectors peer-group
 neighbor reflectors remote-as internal
 neighbor 203.0.113.100 peer-group reflectors
 neighbor 198.51.100.200 peer-group reflectors
 !
 address-family l2vpn evpn
  neighbor reflectors activate
  advertise-all-vni
 exit-address-family
exit
!
ip nht resolve-via-default
!
ipv6 nht resolve-via-default
!
```

Note the `advertise-all-vni` setting. This triggers FRR to identify all SVIs
(bridge devices) which have a VXLAN device attached. You could use route-maps to
filter routes based on VNI or assign and process any communities as per the
enterprise policy. This basic BGP configuration is going to work for all
supervisor hosts and does not require changing when new supervisor hosts are
added or existing ones removed; the route reflectors will ensure they all
receive EVPN routes from all other supervisor hosts.

This documentation is not meant to comprehensively cover BGP, but only provide a
base working configuration.

Assuming that the route reflectors and supervisor hosts have a firewall with a
default-deny policy, no BGP communication will take place just yet. This is
covered in the [Firewall](#firewall) section, below. However, you can still
check that the SVI is detected correctly and the Type 3 EVPN route is included
in the RIB on supervisor hosts, they just won't have any peer to advertise them
to:

```sh
$ ### On supervisor host.

$ sudo vtysh -c 'show evpn vni 100'
VNI: 100
 Type: L2
 Vlan: 1
 Bridge: svi-vpc
 VxLAN interface: vxlan-vpc
 VxLAN ifIndex: 19
 SVI interface: svi-vpc
 SVI ifIndex: 17
 Local VTEP IP: 0.0.0.0
 Mcast group: 0.0.0.0
 Remote VTEPs for this VNI:
 Number of MACs (local and remote) known for this VNI: 0
 Number of ARPs (IPv4 and IPv6, local and remote) known for this VNI: 0
 Advertise-gw-macip: No
 Advertise-svi-macip: No

$ sudo vtysh -c 'show bgp l2vpn evpn'
BGP table version is 45, local router ID is 203.0.113.1
Status codes: s suppressed, d damped, h history, * valid, > best, i - internal
Origin codes: i - IGP, e - EGP, ? - incomplete
EVPN type-1 prefix: [1]:[EthTag]:[ESI]:[IPlen]:[VTEP-IP]:[Frag-id]
EVPN type-2 prefix: [2]:[EthTag]:[MAClen]:[MAC]:[IPlen]:[IP]
EVPN type-3 prefix: [3]:[EthTag]:[IPlen]:[OrigIP]
EVPN type-4 prefix: [4]:[ESI]:[IPlen]:[OrigIP]
EVPN type-5 prefix: [5]:[EthTag]:[IPlen]:[IP]

   Network          Next Hop            Metric LocPrf Weight Path
Route Distinguisher: 203.0.113.1:1
 *> [3]:[0]:[32]:[203.0.113.1]
                    203.0.113.1                        32768 i
                    ET:8 RT:64500:100
```

## IPsec Configuration

As per the configuration so far, supervisor hosts communicate with each other by
exchanging VXLAN-encapsulated Ethernet frames and with the route reflectors
using BGP. The route reflectors establish BGP sessions with each other, while
passively waiting for incoming BGP sessions from supervisor hosts.

In order to provide confidentiality and integrity protection to these data
flows, IPsec can be used. This could be especially important when the underlay
network is untrusted (e.g. the Internet) or when regulatory requirements or the
organisation's policies mandate this. Of course, this section may be skipped
altogether, if IPsec protection is not desired. It is also possible to provide
IPsec protection only for one type of communication (e.g. for the
VXLAN-encapsulated traffic).

This section describes the steps necessary to configure strongSwan in order to
establish on-demand security associations. There are many ways to achieve this
objective, which are outside the scope of this documentation; the examples
provided use public-key authentication using enterprise-managed X.509
certificates. This allows a compromised host to have its access easily revoked,
without the need to reconfigure any other hosts (supervisor hosts or route
reflectors). The cipher suite choice, re-key configuration and certification
revocation setup should follow the organisation's applicable Data Encryption
Standard.

The examples assume there are two private CAs available, one that issues
certificates to route reflectors and one to supervisor hosts. Each host will
have the following files provisioned:
- **/etc/swanctl/private/local.key** – a locally-generate private key; should
  only be readable by the user root and its contents should never leave the
  host.
- **/etc/swanctl/x509/local.crt** – a certificate that authenticates the public
  key of the afore-mentioned private key, signed by one of two private CAs
  (depending on whether the local host is a route reflector or a supervisor
  host).
- **/etc/swanctl/x509ca/reflectors-ca.crt** – the (probably self-signed)
  certificate of the private CA responsible for signing route reflectors'
  certificates.
- **/etc/swanctl/x509ca/supervisors-ca.crt** – the (probably self-signed)
  certificate of the private CA responsible for signing supervisor hosts'
  certificates.

The configuration uses wildcards to identify peers, so the subject names of the
certificates should contain a FQDN within the CN RDN. It is assumed that these
are all under the `example.org` domain name.

The configuration examples use the newer swanctl (VICI-based) configuration, as
set up as per the instructions in the [INSTALL.md](/docs/INSTALL.md)
documentation.

Route reflectors initiate BGP sessions to each other and accept BGP sessions
from other route reflectors and supervisor hosts. The following configuration
would work for that:

```
# /etc/swanctl/conf.d/lxmesh.conf on route reflectors
authorities {
    reflectors {
        cacert = reflectors-ca.crt
        crl_uris = https://ca.example.org/reflectors-ca.crl
    }
    supervisors {
        cacert = supervisors-ca.crt
        crl_uris = https://ca.example.org/supervisors-ca.crl
    }
}
connections {
    bgp {
        local {
            auth = pubkey
            certs = /etc/swanctl/x509/local.crt
        }
        remote {
            auth = pubkey
            id = @*.example.org
            cacerts = /etc/swanctl/x509ca/reflectors-ca.crt,/etc/swanctl/x509ca/supervisors-ca.crt
            revocation = ifuri
        }

        children {
            bgp-in {
                mode = transport
                policies = yes
                local_ts = dynamic[tcp/179]
                remote_ts = dynamic[tcp]
                dpd_action = restart
                start_action = trap
                esp_proposals = chacha20poly1305
            }
            bgp-out {
                mode = transport
                policies = yes
                local_ts = dynamic[tcp]
                remote_ts = dynamic[tcp/179]
                dpd_action = restart
                start_action = trap
                esp_proposals = chacha20poly1305
            }
        }

        version = 2
        mobike = no
        dpd_delay = 10s
        reauth_time = 3h
        keyingtries = 0
        proposals = chacha20poly1305-sha512-x25519
    }
}
```

The configuration on supervisor hosts is quite similar:
```
# /etc/swanctl/conf.d/lxmesh.conf on supervisor hosts
authorities {
    reflectors {
        cacert = reflectors-ca.crt
        crl_uris = https://ca.example.org/reflectors-ca.crl
    }
    supervisors {
        cacert = supervisors-ca.crt
        crl_uris = https://ca.example.org/supervisors-ca.crl
    }
}
connections {
    bgp {
        local {
            auth = pubkey
            certs = /etc/swanctl/x509/local.crt
        }
        remote {
            auth = pubkey
            id = @*.example.org
            cacerts = /etc/swanctl/x509ca/reflectors-ca.crt
            revocation = ifuri
        }

        children {
            bgp-out {
                mode = transport
                policies = yes
                local_ts = dynamic[tcp]
                remote_ts = dynamic[tcp/179]
                dpd_action = restart
                start_action = trap
                esp_proposals = chacha20poly1305
            }
        }

        version = 2
        mobike = no
        dpd_delay = 10s
        reauth_time = 3h
        keyingtries = 0
        proposals = chacha20poly1305-sha512-x25519
    }
    vxlan {
        local {
            auth = pubkey
            certs = /etc/swanctl/x509/local.crt
        }
        remote {
            auth = pubkey
            id = @*.example.org
            cacerts = /etc/swanctl/x509ca/supervisors-ca.crt
            revocation = ifuri
        }

        children {
            vxlan-in {
                mode = transport
                policies = yes
                local_ts = dynamic[udp/4789]
                remote_ts = dynamic[udp]
                dpd_action = restart
                start_action = trap
                esp_proposals = chacha20poly1305
            }
            vxlan-out {
                mode = transport
                policies = yes
                local_ts = dynamic[udp]
                remote_ts = dynamic[udp/4789]
                dpd_action = restart
                start_action = trap
                esp_proposals = chacha20poly1305
            }
        }

        version = 2
        mobike = no
        dpd_delay = 10s
        reauth_time = 3h
        keyingtries = 0
        proposals = chacha20poly1305-sha512-x25519
    }
}
```

Once all the files are in place, restarting the strongSwan daemon will load the
keys and the connections' configuration:

```sh
$ sudo systemctl restart strongswan
```

The cipher suite choice here uses Chacha20-Poly1305 as an AEAD, SHA2-512 as a
hash function and X25519 for key exchange. Note that the cipher suite will
dictate the IPsec overhead, which needs to be taken into account when computing
the MTU associated with the VXLAN interfaces. This is covered in more detail in
the [MTU](#mtu) section, below.

This configuration uses IPsec in transport mode and without UDP encapsulation.
This should be generally fine, including when using the Internet as an underlay
network. IPsec tunnel mode is not required, as the supervisor hosts are the
tunnel endpoints themselves. It the network architecture requires it, tunnel
mode and/or UDP encapsulation could be employed as well, but this needs to be
taken into account when computing the MTU (both would add overhead).

Additionally, notice the value of the `policies` and `start_action` settings.
These cause strongSwan to install an XFRM policy that matches the traffic
selectors; when a packet triggers a policy, IKE negotiation is initiated. This
setup facilitates horizontal scalability, by not requiring prior knowledge of
the IPsec peers. Unfortunately, this means that between the first packet
triggering the IKE negotiation and until a security association is established,
traffic will be dropped. Before LXMesh is declared production-stable,
functionality will be implemented to periodically broadcast a message to all
tunnel endpoints, in order to ensure that security associations are re-created
as soon as possible.

You can verify that the policies are installed appropriately by using the `ip
xfrm policy` command (the `reqid` value is likely to vary):

```sh
$ ### On route reflectors.

$ sudo ip xfrm policy get proto tcp dport 179 dir in
src 0.0.0.0/0 dst 0.0.0.0/0 proto tcp dport 179
	dir in priority 399680
	tmpl src 0.0.0.0 dst 0.0.0.0
		proto esp reqid 1 mode transport

$ sudo ip xfrm policy get proto tcp dport 179 dir out
src 0.0.0.0/0 dst 0.0.0.0/0 proto tcp dport 179
	dir out priority 399680
	tmpl src 0.0.0.0 dst 0.0.0.0
		proto esp reqid 2 mode transport

$ sudo ip xfrm policy get proto tcp sport 179 dir out
src 0.0.0.0/0 dst 0.0.0.0/0 proto tcp sport 179
	dir out priority 399680
	tmpl src 0.0.0.0 dst 0.0.0.0
		proto esp reqid 1 mode transport

$ sudo ip xfrm policy get proto tcp sport 179 dir in
src 0.0.0.0/0 dst 0.0.0.0/0 proto tcp sport 179
	dir in priority 399680
	tmpl src 0.0.0.0 dst 0.0.0.0
		proto esp reqid 2 mode transport

$ ### On supervisor hosts.

$ sudo ip xfrm policy get proto tcp dport 179 dir out
src 0.0.0.0/0 dst 0.0.0.0/0 proto tcp dport 179
	dir out priority 399680
	tmpl src 0.0.0.0 dst 0.0.0.0
		proto esp reqid 3 mode transport

$ sudo ip xfrm policy get proto tcp sport 179 dir in
src 0.0.0.0/0 dst 0.0.0.0/0 proto tcp sport 179
	dir in priority 399680
	tmpl src 0.0.0.0 dst 0.0.0.0
		proto esp reqid 3 mode transport

$ ip xfrm policy get proto udp dport 4789 dir out
src 0.0.0.0/0 dst 0.0.0.0/0 proto udp dport 4789
	dir out priority 399680
	tmpl src 0.0.0.0 dst 0.0.0.0
		proto esp reqid 2 mode transport

$ ip xfrm policy get proto udp dport 4789 dir in
src 0.0.0.0/0 dst 0.0.0.0/0 proto udp dport 4789
	dir in priority 399680
	tmpl src 0.0.0.0 dst 0.0.0.0
		proto esp reqid 1 mode transport
```

If the earlier BGP configuration was applied, the outbound connection attempts
will trigger these policies and initiate IKEv2 negotiations. However, based on
the assumption that the hosts have a firewall with a default-deny policy, the
negotiations will time out. The next section covers the necessary steps in
detail.

## Firewall

This section describes considerations for the hosts' local firewall, as well as
any network firewalls in their communication path. These should be taken into
account and integrated into any firewall policy already applicable.

### Route Reflector Firewall

Route reflectors expect inbound BGP sessions from each other and all supervisor
hosts, but they also initiate outbound BGP sessions to each other. BGP uses TCP
and the default server port is 179; the initiator of the session is likely to
choose an ephemeral port for itself. If IPsec is used to provide confidentiality
and integrity protection to the BGP sessions, a local firewall can enforce this
policy; in this instance, IKE exchanges and ESP (if not using UDP encapsulation)
also need to be allowed through. For example, using nftables and assuming a
stateful firewall that doesn't block outbound traffic:

```
table inet filter {
    set bgp-clients {
        type ipv4_addr
        elements = {
            203.0.113.100,      # route reflector
            198.51.100.200,     # route reflector
            203.0.113.1,        # supervisor host
            203.0.113.2,        # supervisor host
            198.51.100.1,       # supervisor host
        }
    }

    chain filter-input {
        type filter hook input priority filter; policy drop;

        ct state related,established accept
        ct state invalid drop

        ip saddr @bgp-clients meta l4proto esp accept

        tcp dport 179 meta ipsec exists accept
        ip saddr @bgp-clients udp dport 500 accept
    }

    chain filter-output {
        type filter hook output priority filter; policy accept;
    }
}
```

Note that this configuration lists all route reflectors and supervisor hosts in
order to ensure IKE and ESP packets are only allowed through from trusted
sources. While strongSwan and the kernel IPsec implementation should be safe,
there is always a risk that they have yet-undiscovered vulnerabilities.
Considering the route reflectors would normally be configured with the addresses
of all supervisor hosts and other route reflectors (or at least prefixes)
anyway, this setup was chosen as providing better security, at the cost of
configuration management.

Connection tracking for ESP and IKE doesn't really bring much value and could
potentially be a vector for a DoS attack, as the state table has to have a
limit. The following will address this:

```
table inet filter {
    chain raw-prerouting {
        type filter hook prerouting priority raw; policy accept;

        meta l4proto esp notrack
        udp dport 500 notrack
    }

    chain raw-output {
        type filter hook output priority raw; policy accept;

        meta l4proto esp notrack
        udp dport 500 notrack
    }
}
```

Inbound TCP connections for BGP could also not be tracked, but note that FRR
would still retain per-client state, which is a DoS vector in itself, if a host
with a valid private key and associated trusted certificate is compromised. The
firewall could enforce a limit on the number of connections, but doing that
would complicate this example too much.

A network firewall that filters traffic to and from the route reflector would
only see IKEv2 (UDP source/destination port 500) and ESP traffic. Since neither
flow is necessarily initiated by the route reflectors, using a stateful filter
is counter-productive. Without the use of IPsec, it is TCP traffic to and from
the BGP port (by default 179) which would have to be allowed through in both
directions.

### Supervisor Host Firewall

A supervisor host only initiates outbound BGP sessions, but can both receive and
send VXLAN packets to and from all other supervisor hosts. Note that VXLAN
packets only ever have a destination port of 4789 (or whatever is configured)
and, despite using a range for source ports, they are never replied to; this
makes any stateful filtering of them rather wasteful. Similarly to the route
reflectors, if IPsec is in use, IKEv2 and ESP packets would have to be allowed
through, in both directions. The following is an example nftables configuration
which achieves this:

```
table inet filter {
    set route-reflectors {
        type ipv4_addr
        elements = {
            203.0.113.100,
            198.51.100.200,
        }
    }
    set supervisor-hosts {
        type ipv4_addr
        flags interval
        elements = {
            198.51.100.0/24,
            203.0.113.0/24,
        }
    }

    chain filter-input {
        type filter hook input priority filter; policy drop;

        ct state related,established accept
        ct state invalid drop

        ip saddr @route-reflectors meta l4proto esp accept
        ip saddr @supervisor-hosts meta l4proto esp accept

        ip saddr @route-reflectors udp dport 500 accept
        ip saddr @supervisor-hosts udp dport 500 accept

        udp dport 4789 meta ipsec exists accept
    }

    chain filter-output {
        type filter hook output priority filter; policy accept;
    }

    chain raw-prerouting {
        type filter hook prerouting priority raw; policy accept;

        meta l4proto esp notrack
        udp dport { 500, 4789 } notrack
    }

    chain raw-output {
        type filter hook output priority raw; policy accept;

        meta l4proto esp notrack
        udp dport { 500, 4789 } notrack
    }
}
```

Note that this configuration lists the prefixes associated to supervisor hosts.
While this may have the potential to cause issues for scalability, functionality
in LXMesh will be implemented that allows it to dynamically maintain a nftables
set with all addresses of all automatically-discovered supervisor hosts (i.e.
the @supervisor-hosts set above will be maintainable by LXMesh). This will be
done before LXMesh is declared production-ready.

A network firewall that filters traffic to and from the supervisor host would
only see IKEv2 (UDP source/destination port 500) and ESP traffic. Since neither
flow is necessarily initiated by the supervisor host in question, using a
stateful filter is counter-productive. Without the use of IPsec, it is outbound
TCP traffic to the BGP port (by default 179) and inbound and outbound VXLAN
packets with a destination port of 4789 (or whatever is configured) which would
have to be allowed through.

### Reverse-path Filtering

The local firewall on the supervisor hosts may employ a reverse-path check, such
as the following (example using nftables, but also applicable to iptables):

```
table inet filter {
    chain raw-prerouting {
        type filter hook prerouting priority raw; policy accept;

        fib saddr . iif oif 0 drop
    }
}
```

Unfortunately, this kind of test matches and drops MLD queries generated by the
Linux kernel for a bridge device when they are processed by the pseudo-port
represented by the bridge device itself (so when the Linux kernel is supposed to
process a MLD query that it generated itself). This causes issues for multicast
traffic, which is quite problematic for IPv6. However, this can be (relatively)
safely addressed by not performing the check when it comes from link-local
addresses. Depending on the local configuration, the relaxed check could be
restricted to only be applicable to certain interfaces (such as the SVI
interfaces managed by LXMesh). The following is an example of such a check:

```
table inet filter {
    chain raw-prerouting {
        type filter hook prerouting priority raw; policy accept;

        meta protocol ip fib saddr . iif oif 0 drop
        meta protocol ip6 ip6 saddr != fe80::/64 fib saddr . iif oif 0 drop
    }
}
```

Since by default a link-local prefix is assigned to all layer-3 interfaces, this
check would not cause any packets that were previously dropped to be allowed
through (apart from the afore-mentioned MLD queries).

## Intermission

With the firewall configuration in place, the BGP configuration would trigger
the IKEv2 exchanges to take place and IPsec security associations to be
established. This can be verified with something similar to:

```sh
$ ### On supervisor host 203.0.113.1 for route reflector 198.51.100.200.

$ sudo ip xfrm policy get src 203.0.113.1 dst 198.51.100.200 proto tcp dport 179 dir out
src 203.0.113.1/32 dst 198.51.100.200/32 proto tcp dport 179
	dir out priority 366911
	tmpl src 0.0.0.0 dst 0.0.0.0
		proto esp spi 0x71bebb7d reqid 8 mode transport

$ sudo ip xfrm state get src 203.0.113.1 dst 198.51.100.200 proto esp spi 0x71bebb7d
src 203.0.113.1 dst 198.51.100.200
	proto esp spi 0x71bebb7d reqid 8 mode transport
	replay-window 0
	aead rfc7539esp(chacha20,poly1305) 0xbf35cbe60842b6a4224215a27211863d0d63b850a7317f2b383e1f2248b551f550b56bce128
	lastused 2023-11-15 13:03:55
	anti-replay context: seq 0x0, oseq 0x41, bitmap 0x00000000
	sel src 203.0.113.1/32 dst 198.51.100.200/32

$ sudo swanctl --list-sas | grep -m 1 -B 2 -A 8 198.51.100.200
bgp: #1015, ESTABLISHED, IKEv2, 98b2aa927caf4868_i 3fa2ec3627944bb9_r*
  local  'sh1.example.org' @ 203.0.113.1[500]
  remote 'rr2.example.org' @ 198.51.100.200.[500]
  CHACHA20_POLY1305/PRF_HMAC_SHA2_512/CURVE_25519
  established 2629s ago, reauth in 7519s
  bgp-out: #3481, reqid 8, INSTALLED, TRANSPORT, ESP:CHACHA20_POLY1305
    installed 2629s ago, rekeying in 812s, expires in 1331s
    in  f1b8d8f0,   2757 bytes,    88 packets,    48s ago
    out 71bebb7d,   2596 bytes,    88 packets,    48s ago
    local  203.0.113.1/32[tcp]
    remote 198.51.100.200/32[tcp/bgp]
```

The supervisor hosts will now have learned about each other, but there would be
no Ethernet, IPv4 or IPv6 addresses advertised just yet:

```sh
$ ### On supervisor host.

$ sudo vtysh -c 'show evpn vni 100'
VNI: 100
 Type: L2
 Vlan: 1
 Bridge: svi-vpc
 VxLAN interface: vxlan-vpc
 VxLAN ifIndex: 19
 SVI interface: svi-vpc
 SVI ifIndex: 17
 Local VTEP IP: 0.0.0.0
 Mcast group: 0.0.0.0
 Remote VTEPs for this VNI:
  198.51.100.1 flood: HER
  203.0.113.2 flood: HER
 Number of MACs (local and remote) known for this VNI: 0
 Number of ARPs (IPv4 and IPv6, local and remote) known for this VNI: 0
 Advertise-gw-macip: No
 Advertise-svi-macip: No

$ sudo vtysh -c 'show bgp l2vpn evpn'
BGP table version is 45, local router ID is 203.0.113.1
Status codes: s suppressed, d damped, h history, * valid, > best, i - internal
Origin codes: i - IGP, e - EGP, ? - incomplete
EVPN type-1 prefix: [1]:[EthTag]:[ESI]:[IPlen]:[VTEP-IP]:[Frag-id]
EVPN type-2 prefix: [2]:[EthTag]:[MAClen]:[MAC]:[IPlen]:[IP]
EVPN type-3 prefix: [3]:[EthTag]:[IPlen]:[OrigIP]
EVPN type-4 prefix: [4]:[ESI]:[IPlen]:[OrigIP]
EVPN type-5 prefix: [5]:[EthTag]:[IPlen]:[IP]

   Network          Next Hop            Metric LocPrf Weight Path
Route Distinguisher: 203.0.113.1:1
 *> [3]:[0]:[32]:[203.0.113.1]
                    203.0.113.1                        32768 i
                    ET:8 RT:64500:100
Route Distinguisher: 198.51.100.1:1
 *>i[3]:[0]:[32]:[198.51.100.1]
                    198.51.100.1                  100      0 i
                    RT:64500:100 ET:8
 * i[3]:[0]:[32]:[198.51.100.1]
                    198.51.100.1             0    100      0 i
                    RT:64500:100 ET:8
Route Distinguisher: 203.0.113.2:1
 *>i[3]:[0]:[32]:[203.0.113.2]
                    203.0.113.2                   100      0 i
                    RT:64500:100 ET:8
 * i[3]:[0]:[32]:[203.0.113.2]
                    203.0.113.2              0    100      0 i
                    RT:64500:100 ET:8

$ bridge fdb show dev vxlan-vpc
00:53:00:3d:2a:fb vlan 1 master svi-vpc permanent
00:53:00:3d:2a:fb master svi-vpc permanent
00:00:00:00:00:00 dst 198.51.100.1 self permanent
00:00:00:00:00:00 dst 203.0.113.2 self permanent
```

## LXD Container Configuration

With the infrastructure in place, LXD containers can now be configured to join
the virtual network. LXMesh reads container configuration and looks for instance
or network device settings that start with `user.lxmesh.`. These can be
configured either in profiles (which would be recommended for easier
maintenance) or an a per-instance basis. In particular, a container is only
considered by LXMesh if it has at least one device of type `nic`, with `nictype`
set to `p2p` and `user.lxmesh.parent` set. An instance may have any number of
other network devices which would not conflict with LXMesh in any way.  Assuming
that a container with the name `instance1` exists, the following will do the
trick:

```sh
$ ### On supervisor host.

$ sudo lxc config device add instance1 vpc nic name=vpc nictype=p2p user.lxmesh.parent=svi-vpc
```

You can find out the Ethernet address associated to the new device and the
corresponding interface name on the supervisor using:

```sh
$ lxc config show instance1 | grep volatile.vpc
  volatile.vpc.host_name: vethc9c3431d
  volatile.vpc.hwaddr: 00:53:00:10:10:10
```

LXMesh will detect the configuration change and that it is now supposed to
manage that instance's device. It will take the following steps:
- Since the SVI indicated by the `user.lxmesh.parent` setting wasn't previously
  managed, some initialisation takes place at this stage:
  - It will look up the bridge device and potentially modify some settings, as
    documented in the [Bridge Device](#the-bridge-device) section above.
  - If a VXLAN device is associated to it (and it should, as per the prior
    configuration), it will look it up and potentially modify some settings, as
    documented in the [VXLAN Device](#the-vxlan-device) section above.
  - It will add the bridge name to the nftables sets which dictate whether the
    LXMesh-managed rules are applicable or not; in effect, from now on, traffic
    through the SVI will be governed by the LXMesh nftables rules.
  - If enabled via the `dhcp.config-file` configuration file setting, the DHCP
    server configuration file is regenerated and atomically replaced to include
    the new SVI; if the DHCP server is enabled via the `dhcp.server.executable`
    configuration file option, it is either started for the first time or
    restarted, based on whether this was the first SVI managed by LXMesh.
- Adds the host-side interface to the bridge indicated by the
  `user.lxmesh.parent` setting.
- Adds a fowarding table entry to the bridge pointing towards the container's
  interface with the associated Ethernet address. By default, this must match
  the data that LXD keeps (the `volatile.vpc.hwaddr` setting above), in order to
  prevent layer-2 address spoofing; however, you can change this behaviour, as
  documented in the [Address Validation](#address-validation) section below.
- Adds the Ethernet address obtained earlier (which by default will have been
  validated) to a nftables set, with an association to the host-side interface;
  only traffic that matches this set is allowed by the nftables rules.
- Looks at the interface configuration in the container for an IPv6 link-local
  address. By default, this must be constructed using the EUI-64 identifier
  derived from the validated Ethernet address obtained earlier, in order to
  prevent layer-3 address spoofing; however, you can change this behaviour, as
  documented in the [Address Validation](#address-validation) section below.
  Adds a NDP entry on the SVI, pointing to the Ethernet address obtained earlier
  (which by default will have been validated).
- Adds the IPv6 link-local address obtained earlier (which by default will have
  been validated) to a nftables set, with an association to the host-side
  interface; only traffic that matches this set is allowed by the nftables
  rules.

These steps can be confirmed by looking at the nftables ruleset and by running
the following commands:

```sh
$ bridge -d -s fdb show br svi-vpc | grep 00:53:00:10:10:10
00:53:00:10:10:10 dev vethc9c3431d vlan 1 used 432331/432331 extern_learn master svi-vpc
00:53:00:10:10:10 dev vethc9c3431d used 425585/432331 extern_learn master svi-vpc

$ ip -d neigh show dev svi-vpc
fe80::253:ff:fe10:1010 lladdr 00:53:00:10:10:10 PERMANENT proto lxmesh
```

These entries will be picked up by the EVPN implementation and advertised using
Type 2 routes to all other supervisor hosts. You can confirm this by looking at
the BGP RIB and by running identical commands on a different supervisor host:

```sh
$ bridge -d -s fdb show br svi-vpc | grep 00:53:00:10:10:10
00:53:00:10:10:10 dev vxlan-vpc vlan 1 used 419713/419713 extern_learn master svi-vpc
00:53:00:10:10:10 dev vxlan-vpc used 419713/419713 extern_learn master svi-vpc
00:53:00:10:10:10 dev vxlan-vpc dst 203.0.113.1 used 419713/419713 self extern_learn

$ ip -d neigh show dev svi-vpc
fe80::253:ff:fe10:1010 lladdr 00:53:00:10:10:10 extern_learn  NOARP proto zebra
```

Notice that the forwarding table entry points to the VXLAN interface and to the
supervisor host's IP address, while the NDP entry has the **zebra** protocol
instead of **lxmesh**.

If the network interface is raised within the container, it will now be able to
communicate with other containers attached to the same virtual network, whether
on the same supervisor host or not, using IPv6 link-local addressing.
Additionally, router advertisements sent by out systemd-networkd will be
processed, installing both a link route (2001:db8::/64) and a default route
(::/0); neither of these are usable without a globally-scoped address. Please
note that for IPv6 router advertisements to work, the
`general.ip6-all-nodes-address` configuration setting must be set, as described
in the [Multicast](#multicast) section, below.

### Address Assignment

LXMesh supports the assignment of static IPv4 and IPv6 addresses to containers,
whether using static configuration or DHCPv4 and DHCPv6, respectively.
Functionality to support dynamic address assignment may be added at a future
date, but this has not been prioritised as LXMesh was designed with persistent
system containers in mind.

Two per-network-device LXD settings control address assignment:
`user.lxmesh.ipv4.address` and `user.lxmesh.ipv6.address`:

```sh
$ ### On supervisor host.

$ sudo lxc config device set instance1 vpc user.lxmesh.ipv4.address=192.0.2.10 user.lxmesh.ipv6.address=2001:db8::10
```

Associating these two settings results in the following steps being taken:
- The addresses are added to the nftables set with validated addresses,
  associated to the container's host-side interface; the container will be
  allowed to send IPv4 and IPv6 datagrams with these addresses as a source.
- ARP and NDP entries are created, associated to the SVI; these will be
  picked up by the EVPN implementation and distributed via BGP to all other
  supervisor hosts.
- The DHCP hosts file is regenerated and atomically replaced to include the new
  addresses, if enabled via the `dhcp.hosts-file` configuration file setting;
  additionally, if the DHCP server is enabled via the `dhcp.server.executable`
  configuration file setting, the process is sent a SIGHUP signal so that it
  reloads the new hosts file (this behaviour is compatible with dnsmasq).

If the container network configuration has DHCP enabled, the container will now
obtain its addresses from the DHCP server running on its supervisor host. This
can be enabled with the network management system of your choice. For example,
the following systemd-networkd configuration will do the trick:

```ini
# /etc/systemd/network/30-vpc.network
[Match]
Name=vpc
Type=ether

[Link]
RequiredForOnline=no-carrier

[Network]
Description="LXMesh VPC"
ConfigureWithoutCarrier=yes
IgnoreCarrierLoss=3s

DHCP=yes
LinkLocalAddressing=ipv6
IPv6LinkLocalAddressGenerationMode=eui64

IPv6AcceptRA=yes
IPv6PrivacyExtensions=no

[DHCPv4]
UseMTU=yes
```

Please note that LXD recreates the veth network device pair whenever the
container configuration is changed and systemd-networkd in Ubuntu 22.04
(SystemD version 249) will _NOT_ correctly pick up the interface rename and will
leave the interface unconfigured (in a down state); this seems to be a bug. A
workaround is to execute `networkctl reload` within the container after a
change.

Connectivity between containers can be tested by using ICMP echo (ping), as this
is allowed by the default LXMesh firewall configuration.

### Address Validation

LXMesh is meant to protect containers from being able to impersonate each other
or intercept traffic. This is done by validating layer-2 and layer-3 source
addresses in all frames sent by the containers using nftables rules (the
unspecified addresses, 0.0.0.0 and ::, are allowed under certain circumstances)
and by restricting ARP and NDP communication. These addresses must come from a
trusted source, which is why globally-scoped layer-3 addresses must be
statically configured and the link-layer and link-local IPv6 addresses are, by
default, enforced.

LXD persistently stores the container's link-layer address in the
`volatile.[device].hwaddr` configuration setting. This is considered to be a
trusted source and LXMesh will use this value when detecting a container's
link-layer address for validation. A privileged process within the container can
change the link-layer address of the LXMesh-managed network interface to any
value; by default, LXMesh will detect this condition and print a warning log
message, but will continue to only use the trusted address obtained from LXD for
forwarding (in the nftables chain, forwarding table and ARP/NDP entries). This
behaviour can be relaxed by changing the `lxd.enforce-eth-address` configuration
file setting to `no`; the warning message will continue to be printed, but the
link-layer address from the container's runtime state will be used instead.

Similarly, the IPv6 link-local address used by a container must come from a
trusted source. By default, only the link-local address generated using the
EUI-64 identifier derived from the link-layer address is allowed. Assuming the
`lxd.enforce-eth-address` configuration file setting mentioned above is left at
its default `yes`, this establishes a chain of trust for the IPv6 link-local
address. This restriction can be relaxed by setting the
`lxd.enforce-ip6-ll-address` configuration file setting to `no`, which will
allow a container to use any link-local address.

The globally-scoped IPv4 and IPv6 addresses must always come from LXD
configuration, which establishes their trust. Unfortunately, the Linux kernel
does not have an NDP proxy setting, similar to the **IFLA_BRPORT_PROXYARP**
Netlink attribute. NDP responses are only generated when an ND solication comes
from a bridge port with the **IFLA_BRPORT_NEIGH_SUPPRESS** attribute disabled
for an address associated to a port that has the same attribute enabled. In
effect, this means that the NDP proxy only works for addresses belonging to
containers on a different supervisor host; containers on the same supervisor
host must exchange NDP messages themselves in order to communicate. Flooding is
not required, due to the use of multicast, but this still leaves the possibility
of abuse by malicious containers. In fact, until nftables 1.0.9 is available
(which should be in Ubuntu 24.04), a container can send an ND advertisement
message on behalf of a different container.

This vulnerability doesn't allow for a full adversary-in-the-middle attack, but
it still facilitates traffic interception and DoS attacks on the same supervisor
host: container Eve can send an ND solication to container Alice with its own
validated IPv6 source address and link-layer source address, but with container
Bob's IPv6 address in the target field; container Alice will then have an NDP
entry with container Bob's IPv6 address and container Eve's link-layer address.
If container Alice wants to send a datagram to container Bob, it will use Bob's
IPv6 address and Eve's link-layer address as a destination; the datagram will be
forwarded to container Eve. This is only possible when all three containers are
managed by the same supervisor host and note that container Eve does not have
the ability to onward forward the datagram to container Bob as if it came from
container Alice, nor does it have the ability to reply to container Alice
impersonating container Bob.

IPv4 does not suffer from this vulnerability, due to the proxy ARP functionality
provided by the kernel.

### MTU

The MTU of the virtualised overlay network depends on the overhead added by the
tunneling technology, IPsec use and the MTU supported by the underlay network.
The overhead is composed of the following:
- 14 bytes for the Ethernet frame header of the overlay network, as only
  non-VLAN-aware bridges are supported without 802.1Q.
- 8 bytes for the VXLAN header, which encapsulates the Ethernet frame
  transported over the overlay network.
- 8 bytes for the UDP header, which encapsulates the VXLAN datagram.
- A variable number of bytes for the ESP frame, which encpasulates the UDP
  datagram, if IPsec is in use. The ESP overhead is described below.
- 20 bytes for the IPv4 header used in the underlay network. Note that the FRR
  implementation only supports IPv4 for the EVPN underlay, but this may change
  in the future. The IPv4 datagram encapsulates either the ESP frame or the UDP
  datagram, depending on whether IPsec is in use.

The IPsec overhead is dictated by the cipher suite in use and whether tunnel
mode, transport mode or UDP encapsulation are configured. This document
recommends the use of transport mode and no UDP encpasulation, which should work
over the majority of underlay layer-3 networks, including the Internet; this
configuration has the minimum amount of overhead. The ESP frame overhead is
composed the following:
- 8 bytes ESP header
- 1 byte padding length field
- 1 byte next header field
- IV field (initialisation vector): could be 8 or 16 bytes
- ICV field (integrity check value): could be 16 or 32 bytes
- padding: up to 3 bytes, 7 bytes or 15 bytes, depending on the padding
  requirements of the cipher

This means that the minimal overhead for ESP is 34 bytes, assuming no padding is
required. Please note that when computing padding requirements, the maximum size
of the plaintext will need to be taken into account, which is in effect a
function of the underlay network's MTU and the overhead introduced by tunnelling
and IPsec (yes, the definition is recursive). This leads to strange situations,
such as having a 34-byte ESP overhead when the underlay MTU is 1500 bytes, but a
37-byte ESP overhead when the underlay MTU is 1501 bytes for the same cipher
suite.

It is important to compute the overlay MTU correctly, as setting either too-high
or too-low of a value can result in unnecessary packet fragmentation, which
results in inefficient bandwidth use. Packet fragmentation is quite often
offloaded to the network device in modern systems, which can effectively hide
issues, by having the kernel not generate packet-fragmentation-needed ICMP
messages, even when the encapsulated frame with the do-not-fragment flag set
results in an overlay datagram that exceeds the MTU.

Once the correct MTU is set on the VXLAN device, as recommended in the [VXLAN
Device](#the-vxlan-device) section above, the MTU will be copied to the SVI
device as well. systemd-networkd's router advertisement implementation will pick
this up and advertise the correct MTU for the link. As for IPv4, LXMesh will
read the MTU from the SVI and configure dnsmasq to advertise it in DHCP
responses,_ if_ requested. Note that the container configuration using
systemd-networkd as a DHCP client must be expressly configured to request the
MTU option, as described in the [Address Assignment](#address-assignment)
section above. This automatic configuration will not work if the containers are
provisioned using static configuration. In this case, setting the `mtu` option
on the LXD network device will achieve the objective.

### Restricting Container Communication

By default, containers are only allowed to communicate with ICMP echo
requests/responses and control traffic (ARP, IGMP and DHCPv4 for IPv4 and NDP,
RA/RS, MLD and DHCPv6 for IPv6). Additionally, the nftables rules set up by
LXMesh make use of the Linux kernel conntrack facility for a stateful firewall.
Any other communication flows need to be allowed through by using the
`user.lxmesh.in\_services` and `user.lxmesh.out\_services` LXD configuration
settings. These can be applied either on the network device that is managed by
LXMesh or on the instance (directly or through profiles); in the latter case,
the allow-rules are combined with any per-network-device rules and applied to
all LXMesh overlay networks the instance has access to. For example:

```sh
$ ### On supervisor host.

$ sudo lxc config device set instance1 vpc user.lxmesh.in_services=tcp/80,tcp/443 user.lxmesh.out_services=udp/53
```

This will allow the LXD container to receive TCP connections on ports 80 and 443
and initiate UDP message exchanges on port 53. SCTP is also supported, but port
ranges are not. The intention is to add support for LXD-managed network ACLs in
a future release, in order to bring LXMesh firewall configuration in line with
all other LXD connectivity options.

Additionally, the groundwork for supporting a tag-based firewall approach has
been laid, by making use of the netfilter mark and its ability to be carried
over the underlay network with the GBP (Group-Based Policy) extension to VXLAN.
A container can be associated with an arbitrary number of tags using the
`user.lxmesh.tags` setting on a per-network-device or instance basis.
Additionally, tag names are mapped to netfilter marks in the LXMesh
configuration file. For example, the following set up will result in datagrams
sent out by the container to be marked with `0x63` (notice the default SVI
configuration, signalled by not including an SVI name):

```yaml
# /etc/lxmesh/agent.yaml
tags:
    - name:             dns-client
      netfilter-mark:   0x0020
    - name:             ldap-client
      netfilter-mark:   0x0040
svi:
    # Default SVI configuration.
    - netfilter-mark:   0x0003
```

```sh
$ ### On supervisor host.

$ sudo lxc config set instance1 user.lxmesh.tags=dns-client,ldap-client
```

The intention is to allow network ACLs to reference tags (and arbitrary marks)
in order to ease management. Support for this needs to be included in the Linux
kernel nftables implementation (currently in development, as of this writing).

The nftables configuration is designed to not interfere with any other local
firewall configuration. Traffic is only processed by the chains if it originates
from or is directed towards an SVI that LXMesh is explicitely configured to
manage (by having at least one container attached to the VRF using the
`user.lxmesh.parent` LXD configuration). The nftables objects are created within
tables fully-managed by LXMesh. These are assigned the name given by the
`netlink.table` configuration file setting, which defaults to `lxmesh`. Note
that there is a side-effect triggered by the loading of the
nf\_conntrack\_bridge kernel module, as detailed in the
[Architecture](#architecture) section.

## Multicast

LXMesh ensures a correct multicast configuration by taking the following steps:
- Enables the IGMPv3 and MLDv2 querier functionality on the SVIs it manages.
- Enables IGMP and MLD snooping on the SVIs it manages.
- Blocks IGMP and MLD queries from being sent by containers.
- Forwards IGMP and MLD reports from containers to the VXLAN devices, but only
  for SVIs on which multicast is enabled (see below).
- Adds a multicast forwarding table entry for the ff02::16 (all
  MLDv2-capable-routes) on the VXLAN devices associated to SVIs it manages.

Until FRR and the VXLAN driver implement support for RFC9251, overlay multicast
traffic that needs to be transported between supervisor hosts is going to be
flooded using source-based replication (or underlay multicast) to all supervisor
hosts, whether they are interested in it or not. For example, using the
reference architecture described here, if container 2001:db8::50 (running on
supervisor host 198.51.100.1) subscribes to the ff12::cafe group, its MLDv2
reports are flooded to all other supervisor hosts (203.0.113.1 and 203.0.113.2).
If container 2001:db8::10 sends a multicast datagram to ff12::cafe, its
supervisor will replicate the datagram to all supervisor hosts, 198.51.100.1 and
203.0.113.2, even though the latter did not have any containers with
subscriptions. Due to the use of multicast snooping, each supervisor host will
however efficiently forward the multicast datagram only to containers which have
maintained a subscription to the group.

Due to the potential for abuse, this setup is disabled in LXMesh by default.
This is done by not forwarding the container-originated IGMP and MLD reports
over VXLAN tunnels. In effect, this causes the snooping-enabled bridges on all
supervisor hosts to believe that there is no remote container interested in any
multicast traffic, therefore no need to ever flood multicast to the other
supervisor hosts, using source-based replication or underlay multicast. Note
that this does not affect intra-supervisor host multicast traffic in any way,
which will continue to work

If multicast traffic in the overlay network is needed, it can be enabled by
setting the per-SVI `svi.multicast` configuration file option to `on`. For
example, to enable multicast on all SVIs:

```yaml
# /etc/lxmesh/agent.yaml
svi:
    # Default SVI configuration.
    - multicast:    on
```

It's important to note that multicast traffic that is directed at all nodes
(224.0.0.1 and ff02::1) is handled by the Linux kernel just like broadcast
traffic. Therefore, this is effectively disabled by LXMesh. If you need to
generate multicast traffic to all containers on a supervisor host, LXMesh offers
the `general.ip4-all-nodes-address` and `general.ip6-all-nodes-address`
configuration file settings, which are empty by default (but see the note below
about the packaged configuration file). If these are set to a multicast address,
all container host-side veth devices are automatically subscribed to the group
address. Furthermore, datagrams to these addresses are translated to the
standard all-nodes address (224.0.0.1 and ff02::1), before they are delivered to
each local container.

IPv6 router advertisement messages use the all-nodes address ff02::1.
Unfortunately, these datagrams are dropped by the Linux kernel, as they are
handled just like broadcast traffic. Therefore, in order to allow router
advertisement messages to be delivered, LXMesh sets up nftables rules to
translate supervisor-host-originated datagrams destined for the standard
all-nodes address (224.0.0.1 and ff02::1) to the corresponding LXMesh-configured
all-nodes addresses (e.g. 239.255.0.1 and ff12::1), if these are configured.
They would be translated back to the standard all-nodes address before being
delivered to the containers, as mentioned earlier. For this reason, the
configuration file in the packaged LXMesh distribution does include a value for
the `general.ip6-all-nodes-address` setting. Please note that if this is
removed, IPv6 router advertisements will no longer be delivered to containers.

## External Networks

The configuration so far facilitates communication between containers attached
to the same overlay network. If the containers need to communicate with any
other hosts, including processes in the supervisor hosts, the LXMesh firewall
will not intervene (subject to the per-container list of allowed services, of
course), but routing rules will.

Traffic that is originated by the containers will be sent to the gateway address
on the supervisor host (if the containers are provisioned this way, e.g. by
using DHCPv4/DHCPv6). That traffic will be forwarded onwards depending on the
routing rules and whether IPv4/IPv6 forwarding is enabled on the supervisor host
(`net.ipv4.ip_forward` and `net.ipv6.conf.SVI.forwarding` sysctls, which can
also be controlled using the `IPForward` systemd-networkd **.network** file
setting). The default routing rules will use the main routing table on the
supervisor host if the SVI is not enslaved to a VRF or the VRF routing table if
it is (see the section [Traffic Segregation via
VRFs](#traffic-segregation-via-vrfs) below).

For traffic originated by the supervisor hosts to the containers, the supervisor
host must _NOT_ choose the overlay gateway address as a source, as this is
virtualised and used by all other supervisor hosts. There are two ways to
ensure this:
- The _preferred lifetime_ setting of the address can be set to 0, which
  excludes it from the address selection rules. This can be done using the
  `PreferredLifetime` systemd-networkd configuration setting.
- If the SVI is enslaved to a VRF (see the section [Traffic Segregation via
  VRFs](#traffic-segregation-via-vrfs) below), a socket that is not explicitly
  bound to the VRF will not consider the SVI address as a source.

Traffic originated by any other network hosts must be able to reach the
supervisor host that manages the container in question. Since all containers
attached to an overlay network have addresses from the same subnet, LXMesh
facilitates this by creating host routes (/32s and /128s, for IPv4 and IPv6,
respectively) on the supervisor host; these can then be distributed within the
network using a routing protocol, such as BGP. The functionality can be enabled
on a per-SVI basis, using the `svi.host-routes` setting. For example, to enable
it only on the `svi-vpc` SVI:

```yaml
# /etc/lxmesh/agent.yaml
svi:
    - name:         svi-vpc
      host-routes:  yes
```

By default, these host routes will be created in the `main` routing table if the
SVI is not enslaved to a VRF or in the VRF-assigned routing table if it is. For
example, assuming that all three containers in the diagram on this page have been
configured with their respective addresses:

```sh
$ ### On supervisor host 203.0.113.1

$ ip ro show table main dev svi-vpc
192.0.2.10 proto lxmesh scope link
192.0.2.20 proto lxmesh scope link
192.0.2.30 proto lxmesh scope link

$ ip -6 ro show table main dev svi-vpc
2001:db8::10 proto lxmesh metric 1024 pref medium
2001:db8::20 proto lxmesh metric 1024 pref medium
2001:db8::30 proto lxmesh metric 1024 pref medium
```

In order to facilitate easier management, the host routes can also be created in
a different table, using the per-SVI `svi.host-routes-table` configuration file
setting. This could allow simpler selection rules for BGP, for example by using
FRR's `redistribute direct-table` BGP configuration:

```yaml
# /etc/lxmesh/agent.yaml
svi:
    - name:               svi-vpc
      host-routes:        yes
      host-routes-table:  1000
```

The target routing table can be specified either by using a numeric identifier
or a name configured in `/etc/iproute2/rt_tables` /
`/etc/iproute2/rt_tables.d/`. The following FRR configuration for a supervisor
host will advertise the prefixes in the `1000` routing table (which, unless
other systems are also configured, would only contain the LXMesh-managed host
routes). Host routes received from other supervisor hosts will be inserted in
the main routing table (this can facilitate supervisor-host to container
communication when VRFs are used, as described in the section [Traffic
Segregation via VRFs](#traffic-segregation-via-vrfs) below). The rest of the
network can obtain the host routes for all containers from the reflectors. Route
filtering and community tagging should of course follow the enterprise network
architecture in use.

```
# /etc/frr/frr.conf
frr version 9.0.1
frr defaults traditional
log syslog informational
service integrated-vtysh-config
!
router bgp 64500
 no bgp default ipv4-unicast
 neighbor reflectors peer-group
 neighbor reflectors remote-as internal
 neighbor 203.0.113.100 peer-group reflectors
 neighbor 198.51.100.200 peer-group reflectors
 !
 address-family ipv4 unicast
  neighbor reflectors activate
  redistribute table-direct 1000
 exit-address-family
 !
 address-family ipv6 unicast
  neighbor reflectors activate
  redistribute table-direct 1000
 exit-address-family
 !
 address-family l2vpn evpn
  neighbor reflectors activate
  advertise-all-vni
 exit-address-family
exit
!
ip nht resolve-via-default
!
ipv6 nht resolve-via-default
!
```

## Traffic Segregation via VRFs

The supervisor hosts may have access to networks the containers should not
communicate with, such as the Internet. The use of VRFs could provide a simple
solution to this, by using routing tables to restrict forwarding. The following
is an example of associating the previously-configured `svi-vpc` interface with
a VRF. Please note that this requires the installation of the corresponding
`linux-modules-extra-*` package, as described in the
[docs/INSTALL.md](/docs/INSTALL.md) file.

```ini
# /etc/systemd/network/20-vrf-vpc.netdev
[NetDev]
Name=vrf-vpc
Kind=vrf

[VRF]
Table=2000
```

```ini
# /etc/systemd/network/30-vrf-vpc.network
[Match]
Name=vrf-vpc
Kind=vrf

[Link]
RequiredForOnline=no-carrier

[Network]
ConfigureWithoutCarrier=yes
IgnoreCarrierLoss=yes

EmitLLDP=no
IPv6AcceptRA=no
LinkLocalAddressing=no

[Route]
Destination=0.0.0.0/0
Type=prohibit
Table=2000

[Route]
Destination=::/0
Type=prohibit
Table=2000
```

```ini
# /etc/systemd/network/30-svi-vpc.network
[Match]
Name=svi-vpc

[...]

[Network]
VRF=vrf-vpc

[...]
```

Note that it is important to ensure a default route is included in the VRF's
routing table: the default routing rules will result in looking up a destination
in that VRF table if a packet originates from an interface enslaved to the VRF,
but will fall-back to using the main routing table if no match is found.

The supervisor hosts can then use BGP to import prefixes for networks the
containers should be able to communicate with within the VRF's routing table.
The use of BGP layer-3 VPNs (e.g. BGP MPLS/VPN) is not necessary for this and a
policy based on communities and [route
leaking](https://docs.frrouting.org/en/latest/bgp.html#bgp-vrf-route-leaking)
can be implemented instead.

LXMesh will happily manage SVIs enslaved to a VRF. When host routes are
configured, these will be created in the VRF's table, if the
`svi.host-routes-table` configuration file setting is set to `0` or `unspec`
(which is the default).

There is a known issue with dnsmasq not generating DHCPv6 replies properly when
the SVI is enslaved to a VRF. This is likely due to a [kernel
bug](https://lore.kernel.org/netdev/06798029-660D-454E-8628-3A9B9E1AF6F8@safebits.tech/T/#r1eed2f524bec3eb4d27793fa9098779fe5347c9a)
and a [workaround is
implemented](https://thekelleys.org.uk/gitweb/?p=dnsmasq.git;a=commitdiff;h=a889c554a7df71ff93a8299ef96037fbe05f2f55),
but not yet released at the time of this writing.

Also note that when VRFs are in use, datagrams from a container to the local
supervisor host will reach the special `local` routing table just fine, but
datagrams from a supervisor host to a container (whether local or remote) will
require the use of container host routes, as described in the [External
Networks](#external-networks) section above. Additionally, the use of FRR's
`redistribute table`, instead of `redistribute table-direct`, would facilitate
the insertion of host routes for local containers in the `main` routing table.
