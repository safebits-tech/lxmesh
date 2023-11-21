# LXMesh Installation Instructions

This document contains instructions for installing LXMesh on Ubuntu 22.04. While
LXMesh should run on other Linux distributions, as it is a simple Python
application, it has not been tested and it is not packaged for them. However,
these instructions may be applicable to other Debian-derived distributions as
well, as long as the dependencies are taken into account.

## LXD

LXMesh doesn't make any sense without LXD and it needs be installed on each
supervisor host that manages LXD containers in order to facilitate container
connectivity using EVPN technology. LXD should be installed prior to LXMesh, as
the SystemD unit file that starts the LXMesh daemon adds it to the `lxd` group
(which would have to be created). Setting up LXD is outside the scope of this
documentation, but the following steps will ensure it is installed:

```sh
$ sudo apt install snapd
$ sudo snap install lxd
```

## Linux Kernel

LXMesh requires a relatively recent version of the Linux kernel, 6.2 or newer.
This is available in Ubuntu 22.04 via the hardware enablement images (hwe-22.04)
or the edge images in the jammy-updates and jammy-security repositories; some of
the cloud-provider specific kernel images provide an appropriate version, too
(e.g. `linux-image-gcp`). For example, if you have the `linux-image-virtual`
package installed, you can install `linux-image-virtual-hwe-22.04` instead:

```sh
$ sudo apt install linux-image-virtual-hwe-22.04
```

## Dependencies

Most of the dependencies for LXMesh are available in Ubuntu 22.04, with a single
exception: python3-websockets, for which version 10 or newer is required. This
is, however, available in any of the newer Ubuntu releases and can be pulled
from there without any extra dependencies. The following set of instructions
will add the mantic repository, along with a preferences file to ensure that no
other packages are pulled from this newer release. Please make sure you
understand exactly what these steps do before you execute them, as well as the
potential consequences for a future upgrade of the system.

```sh
$ sudo apt install software-properties-common  # For add-apt-repository
$ sudo add-apt-repository -y -n -c universe deb http://archive.ubuntu.com/ubuntu mantic
$ sudo tee /etc/apt/preferences.d/dislike-mantic.pref <<EOF
Package: *
Pin: release a=mantic
Pin-Priority: -1

Package: python3-websockets
Pin: release a=mantic
Pin-Priority: 500
EOF
$ sudo apt update
```

## LXMesh Installation

LXMesh can be installed from its official PPA, **safebits-tech/stable**. Please
make sure you understand the security risks associated with installing software
from a third-party archive, such as this PPA. You have to trust that the
software and its packaging is not malicious now, nor will it ever be, whether by
accident, due to a security breach or by intent. Software supply chains are a
significant risk and you need to understand their implications within the wider
organisational security policy.

LXMesh is provided under the GPLv3 licence. No warranty is provided. Please read
the full licence text and ensure you agree and understand them, before
continuing with the next steps.

```
$ sudo add-apt-repository -y -n ppa:safebits-tech/stable
$ sudo tee /etc/apt/preferences.d/safebits-tech.pref <<EOF
Package: *
Pin: release o=LP-PPA-safebits-tech-stable
Pin-Priority: -1

Package: lxmesh
Pin: release o=LP-PPA-safebits-tech-stable
Pin-Priority: 500
EOF
$ sudo apt update
$ sudo apt install lxmesh
```

## FRR Installation

The LXMesh application facilitates the deployment of an EVPN architecture for
connecting LXD system containers, but does not include an EVPN implementation
itself (nor is it of any use without one). The
[FRRouting](https://frrouting.org) project provides such an implementation,
hence the Recommends dependency of the `lxmesh` package. Note however that
version included in Ubuntu 22.04 has issues within the EVPN implementation –
FRR 9.0.1 or newer is required for the instructions included in the
[docs/USAGE.md](/docs/USAGE.md) documentation. This can be installed from the
project's official [Debian repository](https://deb.frrouting.org). Similarly to
the LXMesh, please ensure that you understand the consequences of this with
regards to the organisational security policy. Any other standards-compliant
EVPN implementation should also work.

## dnsmasq Installation

The LXMesh application can supervise a dnsmasq instance in order to facilitate
provisioning of LXD containers with IPv4 and IPv6 addresses via DHCPv4 and
DHCPv6, respectively. This isn't strictly required, but a very useful part of
the functionality, hence the Recommends dependency of the `lxmesh` package on
the `dnsmasq-base` package (which includes the daemon, but not the SystemD unit
file, as a completely independent instance is managed by LXMesh).

However, please note that there is a known issue with dnsmasq not generating
DHCPv6 replies properly when the used interface is enslaved to a VRF. This is
likely due to a [kernel
bug](https://lore.kernel.org/netdev/06798029-660D-454E-8628-3A9B9E1AF6F8@safebits.tech/T/#r1eed2f524bec3eb4d27793fa9098779fe5347c9a)
and a [workaround is
implemented](https://thekelleys.org.uk/gitweb/?p=dnsmasq.git;a=commitdiff;h=a889c554a7df71ff93a8299ef96037fbe05f2f55),
but not yet released at the time of this writing. If necessary, the patch can
be applied to the version in Ubuntu 22.04, as it is quite basic. The
**safebits-tech/stable** PPA may include a patched version of dnsmasq in the
future.

## strongSwan Installation

The documentation in [docs/USAGE.md](/docs/USAGE.md) recommends using IPsec to
provide confidentiality and integrity protection to packets exchanged between
supervisor hosts, which includes the tunnelled traffic. The examples in that
document use the newer swanctl (VICI-based) configuration and this type of
deployment can be installed from the `charon-systemd` package (the one in Ubuntu
22.04 is just fine, in case you were wondering). Additionally, the X25519 key
exchange and Chacha20-Poly1305 AEAD cipher require the
`libstrongswan-standard-plugins` and `libstrongswan-extra-plugins` packages.
Therefore, for a full installation, the following will do the trick:

```sh
$ sudo apt install charon-systemd libstrongswan-standard-plugins libstrongswan-extra-plugins
```
