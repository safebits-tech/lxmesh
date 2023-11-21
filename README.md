# LXMesh

LXMesh is a Linux networking control-plane application for providing a secure
layer-2 network to [LXD](https://ubuntu.com/lxd) system containers that span
multiple supervisor hosts connected by an arbitrary layer-3 network (such as the
Internet). This is done by leveraging EVPN technology (as provided by
[FRRouting](https://frrouting.org)) and the Linux native bridging and tunnelling
functionality, in order to support a fully distributed and scalable operation.

## Terminology

In order to avoid ambiguity, this section defines (in alphabetical order) some
of the terms that will be used throughout the LXMesh documentation. Terms will
appear here if they can have a different or more general meaning in other
contexts.

- **Container**: The general term may be used to specifically refer to
  persistent system containers, as managed by LXD.
- **Gateway**: A (possibly-abstracted) layer-3 network element that can route
  datagrams to other networks based on layer-3 information (e.g. IPv4/IPv6
  destination address). In particular, **Default Gateway** is used when a
  default route (0.0.0.0/0 or ::/0) is used to direct traffic through the
  **Gateway**.
- **Overlay**: a virtualised layer-2 network that uses tunnelling technology to
  connect **Containers** running on **Supervisor Hosts**, which are in turn
  connected by a layer-3 **Underlay** network.
- **Supervisor Host**: A host that runs LXD to manage system containers.
- **Underlay**: a layer-3 network that provides IP connectivity between
  **Supervisor Hosts**; examples include the Internet or a private enterprise
  network spanning multiple datacentres.

## Topology and Requirements Specification

Consider the following network diagram that highlights supervisor hosts
connected by a layer-3 underlay network, each of them independently managing
multiple LXD system containers. Notice that the supervisor hosts need not be on
the same subnet. The underlay network could be the Internet or a private network
that possibly spans multiple providers and datacentres; the only requirement is
that it provides layer-3 connectivity between the supervisor hosts. By using a
layer-2 overlay network to provide connectivity to the containers and placing
them in the same subnet, they are decoupled from the underlying infrastructure,
which in turns facilitates operations such as migrating containers from one
supervisor host to another.

As can be seen from the addressing example in the diagram, the containers are
configured as if they are in the same layer-2 broadcast domain (using
192.0.2.0/24 for IPv4 and 2001:db8::/64 for IPv6). They are even provisioned
with the same gateway configuration, 192.0.2.1 and 2001:db8::1, which is
independently abstracted by each supervisor host. The containers can use ARP and
NDP respectively to discover link-layer addresses and communicate with
each-other, as if on the same LAN.

![LXMesh basic network diagram](/docs/images/lxmesh-simple.svg)

LXMesh provides an alternative to OVN or using LXD bridge networks with EVPN in
order to implement the topology pictured in the diagram. The latter is a simple
and elegant approach, which can be achieved with just LXD and FRR, but has
several limitations (e.g. broadcast traffic is necessary and, without multicast
support in the underlay, must be source-replicated to all other supervisor
hosts; ACLs are not applicable to inter-container communication). LXMesh is a
control-plane application with a core responsibility of communicating with LXD
and managing Linux networking subsystem objects through Netlink in order to
address those limitations. It has been designed with the following requirements
in mind:

- A trust model that limits the impact that a malicious container can have on
  other containers. This includes:
  - A container should not be able to impersonate another container or
    intercept traffic destined for another container (but see current
    limitations described in [Address
    Validation](/docs/USAGE.md#address-validation); this will be addressed once
    Ubuntu 24.04 is released).
  - A container should not be able to orchestrate a DoS attack that affects
    connectvity for other containers (whether running on the same supervisor
    host or not).
  - A container should not be able to amplify network traffic volume by
    leveraging packet replication (caused by broadcast or multicast traffic).
  - A container should have a limited impact on the control plane, in order to
    minimise its ability to cause a DoS attack.
- Secure-by-default configuration, including taking a default-deny policy
  approach. Some restrictions can be relaxed, but their implications are clearly
  documented; other restrictions cannot be relaxed.
- Horizontal scalability obtained through adding more supervisor hosts, without
  having to modify existing ones in any way. In fact, the configuration of
  supervisor hosts can be identifical. This implies that supervisor hosts
  automatically discover each other.
- Completely distributed operation, without the need for any kind of centralised
  database. LXMesh runs on each supervisor host and does not need to communicate
  with the other LXMesh instances: it only communicates with the local LXD
  daemon and the local kernel. This means that split-horizon scenarios do not
  cause any issues, with the segregated islands continuing to operate
  independently. In fact, LXMesh does not store any state at all, thus not
  burdening the backup and restore procedures in any way.
- Robustness: the Linux networking subsystem configuration must be stable (e.g.
  no blips because of software restarts or crashes) and the system aims for
  eventual consistency. While the network subsystem is not in the desired
  state, LXMesh will in perpetuity attempt to bring it to the desired state
  (but not continuously, so as not to cause a DoS scenario through CPU
  consumption).
- Equally supports both IPv4 and IPv6 for communication between containers and
  between containers and the external networks; supports restricting container
  communication within a VRF.
- Packets between two containers on two different supervisor hosts are
  exchanged directly over the underlay network using unicast tunnels, with no
  third supervisor host acting as an intermediary (thus creating a virtual full
  mesh between supervisor hosts, without the associated configuration
  complexity).
- The ability to use IPsec to protect the confidentiality and integrity of
  packets exchanged between containers running on different supervisor hosts;
  this is particularly important when communication uses an untrusted underlay
  network, such as the Internet.
- Uses existing systems and software where possible and does not interfere with
  them. This allows the system integrator the flexibility of choosing the
  configuration, software and configuration management system that are most
  appropriate to their respective architecture.
- LXMesh runs on the supervisor hosts exclusively and does not interact with the
  containers; the containers do not need any special configuration or software.
- The architecture that LXMesh facilitates is based on open standards and as it
  was intended by them (i.e. the system does not work because of quirks in
  implementations). This allows the system to be integrated into more complex
  architectures, as long as these are also based on or compatible with open
  standards.

In particular, LXMesh only facilitates the implementation of an EVPN
architecture to provide connectivity to LXD containers and it does not
orchestrate the management of the system in any way. This is a relatively light
piece of software, with the hard work performed by the Linux kernel and an EVPN
implementation (such as that in FRR). This documentation explaines how to
configure and integrate the various systems necessary to achieve the desired
functionality, so it can act as a step-by-step tutorial, but the LXMesh software
avoids being opinionated about the software in use or the associated
configuration.

- LXMesh communicates with LXD using the latter's REST API in order to discover
  the containers and their associated configuration that it needs to provide
  connectivity for.
- Forwarding is performed by the Linux native bridging and tunnelling
  functionality. The creation and configuration of the bridge and tunnel network
  devices is not managed by LXMesh. This documentation describes the use of
  systemd-networkd for this purpose, but any other means will work just fine
  (ifupdown, custom scripts, etc.). LXMesh detects the network devices it needs
  to configure and reads their attributes, while only modifying those that are
  required for connectivity.
- Packet filtering is performed by configuring nftables. The tables that LXMesh
  sets up are not going to interact with any tables the system integrator
  configures independently and will not affect traffic not destined for the
  containers that LXMesh is explicitely configured to manage. There is also no
  need to backup or manage the LXMesh tables separately, so any firewall
  management system (including those that use iptables) would work alongside
  just fine. The only limitation is that ebtables will refuse to work, because
  LXMesh creates a table in the bridge family; using nftables to manage other
  tables in the bridge family are unaffected.
- EVPN functionality can be provided by any software, with this documentation
  describing the necessary configuration for FRR. LXMesh does not bundle FRR
  or, for that matter, interact with it in any way. Therefore, any other EVPN
  implementation based on MP-BGP should be comptabible with LXMesh. There are,
  however, some quirks (or possible bugs) of FRR that LXMesh works around.
- IPsec functionality is completely orthogonal: LXMesh doesn't know or care
  about it. This documentation describes a way of configuring strongSwan to
  provide confidentiality and integrity protection for inter-supervisor host
  communication in a way that does not require NxN configuration (i.e. the
  supervisor hosts do not need to be configured with identifiers for all other
  supervisor hosts).
- Address auto-configuration for containers, using DHCPv4 and DHCPv6, is
  facilitated by LXMesh through the use of dnsmasq. In a departure from the
  concept of not being opinionated, LXMesh writes information about addresses
  that need to be assigned to containers in the format that dnsmasq expects and
  the default configuration references dnsmasq as the DHCP server to spawn.
  However, this can be modified through configuration and LXMesh does not depend
  on the DHCP server's behaviour.

How LXMesh works and the functionality it provides is described in detail in the
[USAGE](/docs/USAGE.md) page.

## Environment

The system requires a relatively recent version of the Linux kernel (6.2 or
newer) and an EVPN implementation that supports at least Type 2, Type 3 and
Type 5 routes (FRR 9.0.1 or newer is required, because it addresses a bug). It
has been developed for Ubuntu 22.04 and is also distributed as a binary package
in a PPA, but see the [INSTALL](/docs/INSTALL.md) page for information on
dependencies. That being said, LXMesh is written in Python (requiring Python
3.10 or newer), so it should work on any Linux distribution that can provide
its dependencies.

## Limitations and (Possible) Future Functionality

The following is a non-exhaustive list of the system's limitations which may be
addressed in a future version:

- Only LXD containers are considered and provided connectivity; it should be
  trivial to extend the functionality to LXD VMs as well. It should also be
  possible to extend the support to other container or VM management systems, as
  the majority of the code base is agnostic to LXD.
- Only fixed address assignment is supported; each container that requires
  connectivity via LXMesh must have addresses configured in its instance
  configuration. These can then be provisioned to the containers via
  DHCPv4/DHCPv6 (which is facilitated by LXMesh) or simply statically
  configured. It should be possible to support DHCP dynamic address assignment
  as well, but arbitrary address usage that is not controlled by the supervisor
  host will not be implemented.
- Only EUI-64-based link-local IPv6 address usage is supported, so that they can
  be verified based on information that the supervisor host controls. SEND (RFC
  6494) may be explored as an alternative.
- The EVPN implementation is assumed to use VXLAN and this documentation
  describes how it can be configured. Some properties of the VXLAN network
  devices are managed by LXMesh, but there would no issue in using other
  tunneling technology that's supported by the EVPN implementation (such as
  Geneve), if they are configured appropriately: wrong network settings won't be
  fixed by LXMesh, but the software will certainly not interfere either, in line
  with the stated non-opinionated design goal.
- Network traffic is allowed using very simplistic ACLs, with support for SCTP,
  TCP and UDP; additionally, ICMP echo requests are unconditionally allowed. The
  intention is to implement support for LXD-managed ACLs, in order to provide a
  consistent interface.
- The netfilter rules make use of conntrack to provide a stateful firewall; this
  should be configurable.
- There is a very simplistic implementation of container tags, which is meant to
  provide a scalable way to manage firewall rules. However, at the moment the
  implementation only uses the tags to set the netfilter mark of
  container-originated packets and these are not used in firewall rules in any
  way. Support that will be added to nftables at a future date is required for
  this functionality.
- Multicast traffic between containers running on different supervisor hosts is
  disabled by default because it is difficult to provide a secure-by-default
  configuration. If the underlay network doesn't support multicast delivery
  between the supervisor hosts, multicast traffic would have to be delivered
  using source replication from one supervisor host to **all** other supervisor
  hosts, thus becoming a simple vector for traffic amplification. On the other
  hand, if multicast is supported by the underlay, the use of
  point-to-multipoint (P2MP) tunnels for multicast delivery could make IPsec use
  difficult. However, once support for RFC9251 is included in FRR and the Linux
  VXLAN driver, this default restriction may be relaxed.

You should also read the [Development Status](#development-status) section
below, which describes currently known issues.

## Development Status

LXMesh should be considered in the beta development stage. The software contains
a feature set that supports the architecture described previously, but a number
of steps need to be taken before it is marked as production ready:

- End-to-end and fuzzing tests: as a networking application, the possible states
  are too complex and numerous to cover using unit tests. Therefore, a testing
  framework that generates a large number of initial and desired states and
  tests that the application takes the necessary steps to take the initial state
  to the desired state would provide better coverage. Additionally, fuzzing
  usingly randomly generated states and events can be used to complement the
  fact that the dynamically generated tests mentioned earlier cannot cover all
  possible scenarios for large deployments due to too huge of a state space.
- A public policy on the software development and distribution security, so that
  risks to the software supply chain can be appropriately ascertained.
- A public maintenance policy.
- A public vulnerability disclosure policy.
- Documentation for developers on the software's design and code structure, so
  that maintenance can more easily be picked up by others.
- It is currently possible for a container to send IPv6 neighbour discovery
  advertisements that spoof the address of a different container, but only
  within the same supervisor host. This allows traffic to be intercepted, but an
  active or passive adversary-in-the-middle attack cannot be mounted, as it is
  not possible to subsequently forward traffic to its originally intended
  destination; this therefore becomes a DoS attack. The issue will be addressed
  when Ubuntu 24.04 is released, as a fix requires nftables 1.0.9 or newer.
- LXMesh needs to be run with several network-related capabilities; an AppArmor
  profile needs to be developed to restrict access as much as possible.

These items will be clearly marked here as they are implemented.

## Next Steps

The following pages form the rest of the LXMesh documentation:

- [docs/INSTALL.md](/docs/INSTALL.md): software installation instruction,
  including a description of dependencies.
- [docs/USAGE.md](/docs/USAGE.md): a tutorial-style description of how LXMesh
  operates, how to configure it and other software in order to implement the
  EVPN architecture described in the earlier [Topology and Requirements
  Specification](#topology-and-requirements-specification) section.
