"""Rendering a planned node as the configuration its platform would really emit.

One function per platform, each taking a `Node` and returning text the shipped parser
accepts. Nothing here is decorative: every construct is one a parser reads, because a
line no parser touches contributes nothing to the NCM and therefore nothing to any
feature being tested.

**Hardening is the variable that matters.** A weak device fails the checks a real
neglected switch fails — telnet, default communities, no AAA, no timeout, clear-text
passwords — and a hardened one passes them. Without that spread a findings console is
either empty or uniformly red, and neither is a thing worth looking at.

The firewall renderers additionally carry rules that are *deliberately* flawed on the
weaker devices: a deny above an allow it shadows, an any-any permit with logging off, a
duplicated address object. Those are what the rulebase analysis exists to find, and an
estate of clean rulebases leaves it with nothing to report.
"""

from __future__ import annotations

import ipaddress
import json

from synthetic.plan import Hardening, Node, Tier


def _netmask(cidr: str) -> tuple[str, str]:
    """An `address/prefix` split into the dotted-quad pair older platforms want."""
    interface = ipaddress.ip_interface(cidr)
    return str(interface.ip), str(interface.netmask)


def _network(cidr: str) -> str:
    return str(ipaddress.ip_interface(cidr).network)


def _vlan_id(name: str, *, default: int = 1) -> int:
    """The VLAN number an interface name implies.

    `default` matters more than it looks. A core router's legs are called `uplink`,
    `distribution` and `dmz-transit-1`, and two of those carry no digits at all — so a
    fixed fallback rendered three separate `interface Vlan1` blocks on one device, each
    with a different address. No switch has three Vlan1 SVIs, and the parser dutifully
    recorded three interfaces sharing a name.
    """
    digits = "".join(ch for ch in name if ch.isdigit())
    return int(digits) if digits else default


# ───────────────────────────── Cisco IOS ─────────────────────────────────────


def cisco_ios(node: Node) -> str:
    weak = node.hardening is Hardening.WEAK
    hardened = node.hardening is Hardening.HARDENED
    version = "15.2" if weak else "17.9"

    lines = [
        "!",
        f"! {node.hostname} — {node.purpose}",
        "!",
        f"version {version}",
        "service timestamps debug datetime msec",
        "service timestamps log datetime msec",
        "no service password-encryption" if weak else "service password-encryption",
        "!",
        f"hostname {node.hostname}",
        "!",
    ]

    if weak:
        lines += [
            "no aaa new-model",
            "enable password cisco123",
            "username admin privilege 15 password 0 Admin123",
            "!",
            "ip http server",
            "ip source-route",
            "service tcp-small-servers",
            "service udp-small-servers",
            "!",
        ]
    else:
        lines += [
            "aaa new-model",
            "aaa authentication login default group TACACS-GRP local",
            "aaa authorization exec default group TACACS-GRP local",
            "aaa accounting exec default start-stop group TACACS-GRP",
            "aaa accounting commands 15 default start-stop group TACACS-GRP",
            "enable secret 9 $9$abcdefghijklmnopqrstuvwxyz0123456789ABCDEF",
            "username netops privilege 15 secret 9 $9$zyxwvutsrqponmlkjihgfedcba9876543210",
            "!",
            "no ip http server",
            "no ip source-route",
            "ip ssh version 2",
            f"tacacs server TACACS-GRP{chr(10)} address ipv4 10.100.{node.site}.30"
            f"{chr(10)} key 7 08351F1B4A0C0A0E",
            "!",
        ]

    lines += [f"ip domain-name site{node.site}.example.net", "!"]

    for name, cidr in node.interfaces.items():
        address, mask = _netmask(cidr)
        vlan = _vlan_id(name)
        lines += [
            f"interface Vlan{vlan}",
            f" description {name.upper()}",
            f" ip address {address} {mask}",
            "" if weak else " no ip redirects",
            "" if weak else " no ip proxy-arp",
            " no shutdown",
            "!",
        ]

    # A physical port or two, so interface counts are not all SVIs.
    lines += [
        "interface GigabitEthernet1/0/1",
        " description UPLINK",
        " switchport mode trunk" if node.tier is Tier.ACCESS_SWITCH else " no switchport",
        " no shutdown",
        "!",
    ]

    for prefix, next_hop in node.routes.items():
        if next_hop == "connected":
            continue
        network, mask = _netmask(prefix) if "/" in prefix else (prefix, "255.255.255.0")
        network = str(ipaddress.ip_network(prefix, strict=False).network_address)
        mask = str(ipaddress.ip_network(prefix, strict=False).netmask)
        lines.append(f"ip route {network} {mask} {next_hop}")
    lines.append("!")

    if weak:
        lines += [
            "snmp-server community public RO",
            "snmp-server community private RW",
            "!",
            "line con 0",
            " exec-timeout 0 0",
            "line vty 0 4",
            " exec-timeout 0 0",
            " password cisco",
            " login",
            " transport input telnet ssh",
            " transport output telnet",
            "line vty 5 15",
            " exec-timeout 0 0",
            " transport input all",
            "!",
        ]
    else:
        community = f"ro-{node.site}{node.hostname[-3:]}"
        lines += [
            f"snmp-server community {community} RO 99",
            "snmp-server group monitor v3 priv",
            "!",
            f"logging host 10.100.{node.site}.10",
            f"logging host 10.100.{node.site}.11",
            "logging trap informational",
            f"ntp server 10.100.{node.site}.40",
            f"ntp server 10.100.{node.site}.41",
            "!",
            "access-list 99 permit 10.100.0.0 0.0.255.255",
            "access-list 99 deny   any log",
            "!",
            "line con 0",
            " exec-timeout 5 0",
            " logging synchronous",
            "line vty 0 4",
            " exec-timeout 10 0" if not hardened else " exec-timeout 5 0",
            " transport input ssh",
            " transport output none",
            " access-class 99 in",
            "line vty 5 15",
            " exec-timeout 10 0",
            " transport input ssh",
            " transport output none",
            "!",
        ]

    lines += [
        "banner motd ^C",
        "Authorised access only. Activity is monitored and recorded.",
        "^C",
        "!",
        "end",
        "",
    ]
    return "\n".join(line for line in lines if line != "")


# ───────────────────────────── Cisco NX-OS ───────────────────────────────────


def cisco_nxos(node: Node) -> str:
    weak = node.hardening is Hardening.WEAK

    lines = [
        "!Command: show running-config",
        f"! {node.hostname} — {node.purpose}",
        "!",
        "version 10.3(4a)" if not weak else "version 9.3(5)",
        f"hostname {node.hostname}",
        "!",
        "feature ssh",
        "feature interface-vlan",
        "feature ospf",
        "!",
    ]

    if weak:
        lines += [
            "no password strength-check",
            "username admin password 0 Admin123 role network-admin",
            "feature telnet",
            "!",
            "snmp-server community public group network-operator",
            "snmp-server community private group network-admin",
            "!",
        ]
    else:
        lines += [
            "password strength-check",
            "username netops password 5 $5$abcdefgh$ijklmnopqrstuvwxyz role network-admin",
            "no feature telnet",
            "ssh key rsa 2048",
            "!",
            "aaa authentication login default group TACACS-GRP local",
            "aaa authentication login console local",
            "aaa accounting default group TACACS-GRP",
            f"tacacs-server host 10.100.{node.site}.30 key 7 08351F1B4A0C0A0E timeout 5",
            "aaa group server tacacs+ TACACS-GRP",
            f"    server 10.100.{node.site}.30",
            "    use-vrf management",
            "!",
            "snmp-server user monitor network-operator auth md5 0x1234abcd priv 0xdeadbeef"
            " localizedkey",
            f"snmp-server host 10.100.{node.site}.20 traps version 3 priv monitor",
            "!",
            f"logging server 10.100.{node.site}.10 5 use-vrf management",
            f"logging server 10.100.{node.site}.11 5 use-vrf management",
            "logging timestamp milliseconds",
            f"ntp server 10.100.{node.site}.40 use-vrf management",
            "!",
        ]

    lines += [
        "spanning-tree mode rapid-pvst",
        "ip dhcp snooping" if not weak else "no ip dhcp snooping",
        "!",
    ]

    # One numbering for both loops: the VLAN declared here and the SVI configured below
    # have to agree, and a name with no digits in it — `uplink`, `distribution` — gets a
    # distinct number from its position rather than all of them colliding on Vlan1.
    vlans = {
        name: _vlan_id(name, default=900 + index) for index, name in enumerate(node.interfaces)
    }

    for name, vlan in vlans.items():
        lines += [
            f"vlan {vlan}",
            f"  name {name.upper().replace('-', '_')}",
        ]
    lines.append("!")

    for name, cidr in node.interfaces.items():
        lines += [
            f"interface Vlan{vlans[name]}",
            f"  description {name.upper()}",
            "  no shutdown",
            f"  ip address {cidr}",
            "!",
        ]

    lines += [
        "interface mgmt0",
        "  vrf member management",
        f"  ip address {node.mgmt_ip}/24",
        "!",
    ]

    for prefix, next_hop in node.routes.items():
        if next_hop == "connected":
            continue
        lines.append(f"ip route {prefix} {next_hop}")
    lines.append("!")

    lines += [
        "line vty",
        "  exec-timeout 0" if weak else "  exec-timeout 10",
        "!",
        "",
    ]
    return "\n".join(lines)


# ───────────────────────────── Cisco ASA ─────────────────────────────────────


def cisco_asa(node: Node) -> str:
    weak = node.hardening is Hardening.WEAK
    site_net = f"10.{20 + node.site}.0.0"
    dmz = next((c for n, c in node.interfaces.items() if n == "dmz"), None)

    lines = [
        ": Saved",
        f": {node.hostname} — {node.purpose}",
        "ASA Version 9.12(4)" if weak else "ASA Version 9.18(2)",
        f"hostname {node.hostname}",
        "names",
        "!",
    ]

    for index, (name, cidr) in enumerate(node.interfaces.items()):
        address, mask = _netmask(cidr)
        level = 0 if name == "outside" else (50 if name == "dmz" else 100)
        lines += [
            f"interface GigabitEthernet0/{index}",
            f" nameif {name}",
            f" security-level {level}",
            f" ip address {address} {mask}",
            " no shutdown",
            "!",
        ]

    lines += [
        f"object network OBJ-SITE-NET{chr(10)} subnet {site_net} 255.255.0.0",
        "object network OBJ-MGMT-NET",
        f" subnet 10.100.{node.site}.0 255.255.255.0",
        "object service SVC-HTTPS",
        " service tcp destination eq 443",
        "!",
    ]
    if dmz:
        lines += [
            "object network OBJ-DMZ-WEB",
            f" host {ipaddress.ip_interface(dmz).ip + 9!s}",
            "!",
        ]

    # The rulebase. On a weak device the first two entries shadow each other and the
    # any-any permit is unlogged, which is exactly what the analysis should surface.
    if weak:
        lines += [
            "access-list OUTSIDE-IN extended deny tcp any any eq 3389",
            "access-list OUTSIDE-IN extended permit tcp any any eq 3389",
            "access-list OUTSIDE-IN extended permit ip any any",
            "access-list OUTSIDE-IN extended permit tcp any any eq 443 log",
            "!",
        ]
    else:
        lines += [
            f"access-list OUTSIDE-IN extended permit tcp any {site_net} 255.255.0.0 eq 443 log",
            "access-list OUTSIDE-IN extended deny ip any any log",
            "!",
            f"access-list INSIDE-OUT extended permit ip {site_net} 255.255.0.0 any log",
            "access-list INSIDE-OUT extended deny ip any any log",
            "!",
        ]

    # Writing an access list and binding it are separate acts on an ASA, and a list
    # bound to nothing filters nothing — the parser records that as `applied: false` and
    # the map will not count the device as a control. This used to key on an interface
    # literally named `outside`, which a segment firewall does not have (its legs are
    # `inside` and `dmz`), so four of the twelve ASAs in the estate enforced nothing at
    # all while looking like firewalls everywhere else.
    #
    # The untrusted side is `outside` where there is one and the transit leg otherwise:
    # on a segment firewall the rest of the site is what the DMZ is being protected from.
    untrusted = "outside" if "outside" in node.interfaces else next(iter(node.interfaces), None)
    if untrusted:
        lines.append(f"access-group OUTSIDE-IN in interface {untrusted}")
    # The second binding is deliberately skipped on a weak device: egress filtering
    # written and never applied is a real and common finding.
    protected = next((name for name in node.interfaces if name != untrusted), None)
    if protected and not weak:
        lines.append(f"access-group INSIDE-OUT in interface {protected}")
    lines.append("!")

    outside = "outside" if "outside" in node.interfaces else next(iter(node.interfaces))
    inside = "inside" if "inside" in node.interfaces else outside
    lines += [
        f"nat ({inside},{outside}) source dynamic OBJ-SITE-NET interface",
        "!",
    ]

    for prefix, next_hop in node.routes.items():
        if next_hop == "connected":
            continue
        network = str(ipaddress.ip_network(prefix, strict=False).network_address)
        mask = str(ipaddress.ip_network(prefix, strict=False).netmask)
        via = outside if prefix == "0.0.0.0/0" else inside
        lines.append(f"route {via} {network} {mask} {next_hop} 1")
    lines.append("!")

    if weak:
        lines += [
            "username admin password Admin123 privilege 15",
            "snmp-server community public",
            "telnet 0.0.0.0 0.0.0.0 inside",
            "telnet timeout 30",
            "!",
        ]
    else:
        lines += [
            "aaa-server TACACS-GRP protocol tacacs+",
            f"aaa-server TACACS-GRP (inside) host 10.100.{node.site}.30",
            " key *****",
            "aaa authentication ssh console TACACS-GRP LOCAL",
            "aaa authorization exec authentication-server",
            "aaa accounting command TACACS-GRP",
            "username netops password ***** privilege 15",
            "!",
            "snmp-server group monitor v3 priv",
            f"snmp-server host inside 10.100.{node.site}.20 version 3 monitor",
            f"ssh 10.100.{node.site}.0 255.255.255.0 inside",
            "ssh version 2",
            "ssh timeout 10",
            "no telnet 0.0.0.0 0.0.0.0 inside",
            "!",
            f"logging host inside 10.100.{node.site}.10",
            "logging enable",
            "logging trap informational",
            f"ntp server 10.100.{node.site}.40",
            "!",
        ]

    lines += ["banner motd Authorised access only.", "!", ": end", ""]
    return "\n".join(lines)


# ───────────────────────────── FortiOS ───────────────────────────────────────


def fortios(node: Node) -> str:
    weak = node.hardening is Hardening.WEAK
    site_net = f"10.{20 + node.site}.0.0 255.255.0.0"

    out: list[str] = [
        f"#config-version=FGT-7.2.5 {node.hostname}",
        "config system global",
        f'    set hostname "{node.hostname}"',
        "    set admin-https-redirect enable" if not weak else "    set admintelnet enable",
        f"    set admintimeout {'480' if weak else '10'}",
        "    set strong-crypto enable" if not weak else "    set strong-crypto disable",
        "end",
        "config system password-policy",
        f"    set status {'disable' if weak else 'enable'}",
        "    set minimum-length 14" if not weak else "",
        "end",
        "config system interface",
    ]
    for name, cidr in node.interfaces.items():
        address, mask = _netmask(cidr)
        role = "wan" if name in ("outside", "wan1") else "lan"
        out += [
            f'    edit "{name}"',
            f"        set ip {address} {mask}",
            f"        set allowaccess {'ping https ssh telnet' if weak else 'ping https ssh'}",
            f"        set role {role}",
            "    next",
        ]
    out.append("end")

    out += [
        "config system admin",
        '    edit "admin"',
        '        set accprofile "super_admin"',
        f"        set trusthosts1 {'0.0.0.0 0.0.0.0' if weak else f'10.100.{node.site}.0 255.255.255.0'}",
        "    next",
        "end",
        "config log syslogd setting",
        f"    set status {'disable' if weak else 'enable'}",
        f'    set server "10.100.{node.site}.10"',
        "end",
        "config system ntp",
        "    set ntpsync enable",
        "    config ntpserver",
        "        edit 1",
        f'            set server "10.100.{node.site}.40"',
        "        next",
        "    end",
        "end",
        "config system snmp community",
        "    edit 1",
        f'        set name "{"public" if weak else f"ro-site{node.site}"}"',
        "    next",
        "end",
        "config firewall address",
        '    edit "site-net"',
        f"        set subnet {site_net}",
        "    next",
        '    edit "mgmt-net"',
        f"        set subnet 10.100.{node.site}.0 255.255.255.0",
        "    next",
    ]
    if weak:
        # A duplicate object, for the hygiene analysis to find.
        out += [
            '    edit "site-net-copy"',
            f"        set subnet {site_net}",
            "    next",
        ]
    out.append("end")

    dmz = node.interfaces.get("dmz")
    if dmz:
        vip_external = str(ipaddress.ip_interface(node.interfaces["inside"]).ip)
        out += [
            "config firewall vip",
            '    edit "dmz-web-vip"',
            f"        set extip {vip_external}",
            f'        set mappedip "{ipaddress.ip_interface(dmz).ip + 9!s}"',
            '        set extintf "inside"',
            "        set portforward enable",
            "        set protocol tcp",
            "        set extport 443",
            "        set mappedport 8443",
            "    next",
            "end",
        ]

    zones = list(node.interfaces)
    src_if, dst_if = (zones + zones)[0], (zones + zones)[1] if len(zones) > 1 else zones[0]
    out += ["config firewall policy"]
    if weak:
        out += [
            "    edit 1",
            f'        set srcintf "{src_if}"',
            f'        set dstintf "{dst_if}"',
            '        set srcaddr "all"',
            '        set dstaddr "all"',
            "        set action accept",
            '        set schedule "always"',
            '        set service "ALL"',
            "        set logtraffic disable",
            "    next",
        ]
    else:
        out += [
            "    edit 1",
            f'        set srcintf "{src_if}"',
            f'        set dstintf "{dst_if}"',
            '        set srcaddr "site-net"',
            '        set dstaddr "all"',
            "        set action accept",
            '        set schedule "always"',
            '        set service "HTTPS" "DNS"',
            "        set logtraffic all",
            "        set utm-status enable",
            '        set ssl-ssh-profile "certificate-inspection"',
            "    next",
            "    edit 2",
            f'        set srcintf "{src_if}"',
            f'        set dstintf "{dst_if}"',
            '        set srcaddr "all"',
            '        set dstaddr "all"',
            "        set action deny",
            '        set schedule "always"',
            '        set service "ALL"',
            "        set logtraffic all",
            "    next",
        ]
    out.append("end")

    out.append("config router static")
    edit = 1
    for prefix, next_hop in node.routes.items():
        if next_hop == "connected":
            continue
        device = "outside" if prefix == "0.0.0.0/0" else next(iter(node.interfaces))
        device = "inside" if "inside" in node.interfaces and prefix != "0.0.0.0/0" else device
        out.append(f"    edit {edit}")
        if prefix != "0.0.0.0/0":
            network = ipaddress.ip_network(prefix, strict=False)
            out.append(f"        set dst {network.network_address} {network.netmask}")
        out += [
            f"        set gateway {next_hop}",
            f'        set device "{device}"',
            "    next",
        ]
        edit += 1
    out += ["end", ""]

    return "\n".join(line for line in out if line != "")


# ───────────────────────────── PAN-OS ────────────────────────────────────────


def panos(node: Node) -> str:
    weak = node.hardening is Hardening.WEAK
    site_net = f"10.{20 + node.site}.0.0/16"
    interfaces = list(node.interfaces.items())

    def zone_for(name: str) -> str:
        return "untrust" if name in ("outside", "wan1") else ("dmz" if name == "dmz" else "trust")

    iface_xml = []
    zone_xml = []
    for index, (name, cidr) in enumerate(interfaces, start=1):
        iface_xml.append(
            f'<entry name="ethernet1/{index}"><layer3><ip>'
            f'<entry name="{cidr}"/></ip></layer3></entry>'
        )
        zone_xml.append(
            f'<entry name="{zone_for(name)}"><network><layer3>'
            f"<member>ethernet1/{index}</member></layer3></network></entry>"
        )

    route_xml = []
    for prefix, next_hop in node.routes.items():
        if next_hop == "connected":
            continue
        route_xml.append(
            f'<entry name="route-{len(route_xml) + 1}">'
            f"<destination>{prefix}</destination>"
            f"<nexthop><ip-address>{next_hop}</ip-address></nexthop>"
            f"<interface>ethernet1/1</interface></entry>"
        )

    if weak:
        rules = """
<entry name="block-rdp"><from><member>untrust</member></from>
<to><member>trust</member></to><source><member>any</member></source>
<destination><member>any</member></destination><service><member>service-rdp</member></service>
<application><member>any</member></application><action>deny</action></entry>
<entry name="partner-rdp"><from><member>untrust</member></from>
<to><member>trust</member></to><source><member>any</member></source>
<destination><member>any</member></destination><service><member>service-rdp</member></service>
<application><member>any</member></application><action>allow</action></entry>
<entry name="permit-any"><from><member>any</member></from><to><member>any</member></to>
<source><member>any</member></source><destination><member>any</member></destination>
<service><member>any</member></service><application><member>any</member></application>
<action>allow</action></entry>
<entry name="old-migration"><from><member>any</member></from><to><member>any</member></to>
<source><member>any</member></source><destination><member>any</member></destination>
<service><member>any</member></service><application><member>any</member></application>
<action>allow</action><disabled>yes</disabled></entry>
"""
        addresses = f"""
<entry name="site-net"><ip-netmask>{site_net}</ip-netmask></entry>
<entry name="site-net-copy"><ip-netmask>{site_net}</ip-netmask></entry>
<entry name="never-used"><ip-netmask>192.0.2.0/24</ip-netmask></entry>
"""
    else:
        rules = """
<entry name="inbound-web"><from><member>untrust</member></from><to><member>trust</member></to>
<source><member>any</member></source><destination><member>site-net</member></destination>
<service><member>service-https</member></service>
<application><member>web-browsing</member></application><action>allow</action>
<log-end>yes</log-end><profile-setting><group><member>strict</member></group></profile-setting>
</entry>
<entry name="outbound"><from><member>trust</member></from><to><member>untrust</member></to>
<source><member>site-net</member></source><destination><member>any</member></destination>
<service><member>application-default</member></service>
<application><member>any</member></application><action>allow</action><log-end>yes</log-end>
</entry>
<entry name="deny-rest"><from><member>any</member></from><to><member>any</member></to>
<source><member>any</member></source><destination><member>any</member></destination>
<service><member>any</member></service><application><member>any</member></application>
<action>deny</action><log-end>yes</log-end></entry>
"""
        addresses = f'<entry name="site-net"><ip-netmask>{site_net}</ip-netmask></entry>'

    login_banner = "" if weak else "<login-banner>Authorised access only.</login-banner>"
    telnet = "<telnet>yes</telnet>" if weak else "<telnet>no</telnet><ssh>yes</ssh>"

    return f"""<?xml version="1.0"?>
<config version="11.0.0" urldb="paloaltonetworks">
  <mgt-config><users>
    <entry name="admin"><permissions><role-based><superuser>yes</superuser></role-based>
    </permissions></entry>
  </users></mgt-config>
  <shared><log-settings><syslog><entry name="siem"><server>
    <entry name="siem-01"><server>10.100.{node.site}.10</server><transport>TCP</transport>
    </entry></server></entry></syslog></log-settings></shared>
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <hostname>{node.hostname}</hostname>
          <ip-address>{node.mgmt_ip}</ip-address>
          <timezone>UTC</timezone>
          {login_banner}
          <service>{telnet}</service>
          <ntp-servers><primary-ntp-server><ntp-server-address>10.100.{node.site}.40
          </ntp-server-address></primary-ntp-server></ntp-servers>
          <snmp-setting><access-setting><version>
          {"<v2c><snmp-community-string>public</snmp-community-string></v2c>" if weak else "<v3/>"}
          </version></access-setting></snmp-setting>
        </system>
      </deviceconfig>
      <network>
        <interface><ethernet>{"".join(iface_xml)}</ethernet></interface>
        <virtual-router><entry name="default"><routing-table><ip><static-route>
          {"".join(route_xml)}
        </static-route></ip></routing-table></entry></virtual-router>
      </network>
      <vsys>
        <entry name="vsys1">
          <zone>{"".join(zone_xml)}</zone>
          <address>{addresses}</address>
          <rulebase>
            <security><rules>{rules}</rules></security>
            <nat><rules>
              <entry name="outbound-nat">
                <source><member>site-net</member></source>
                <destination><member>any</member></destination>
                <service>any</service>
                <source-translation><dynamic-ip-and-port><interface-address>
                  <interface>ethernet1/1</interface>
                </interface-address></dynamic-ip-and-port></source-translation>
              </entry>
            </rules></nat>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
"""


# ───────────────────────────── Check Point Gaia ──────────────────────────────


def checkpoint_gaia(node: Node) -> str:
    weak = node.hardening is Hardening.WEAK
    lines = [
        "# Check Point Gaia — show configuration",
        f"# {node.hostname} — {node.purpose}",
        "Product version Check Point Gaia R81.20",
        "OS build 631",
        f"set hostname {node.hostname}",
    ]

    for index, (name, cidr) in enumerate(node.interfaces.items()):
        interface = ipaddress.ip_interface(cidr)
        lines += [
            f"set interface eth{index} state on",
            f"set interface eth{index} ipv4-address {interface.ip} "
            f"mask-length {interface.network.prefixlen}",
            f'set interface eth{index} comments "{name}"',
        ]

    for prefix, next_hop in node.routes.items():
        if next_hop == "connected":
            continue
        lines.append(f"set static-route {prefix} nexthop gateway address {next_hop} on")

    if weak:
        lines += [
            "set snmp community public read-only",
            "set snmp agent on",
            "set user admin shell /bin/bash",
            "set password-controls min-password-length 6",
            "set password-controls complexity 1",
            "set net-access telnet on",
        ]
    else:
        lines += [
            f"set snmp community ro-site{node.site} read-only",
            "set snmp agent on",
            "set snmp agent-version v3-only",
            "set user admin shell /etc/cli.sh",
            "set password-controls min-password-length 14",
            "set password-controls complexity 3",
            "set password-controls password-expiration 90",
            "set net-access telnet off",
            "set net-access ssh on",
            # `add`, not `set`: Gaia adds list members and sets scalars, and the parser
            # keys on the verb. Writing `set syslog log-remote-address` renders a file
            # that looks right and contributes no syslog server at all.
            f"add syslog log-remote-address 10.100.{node.site}.10 level info",
            f"add ntp server primary 10.100.{node.site}.40 version 4",
            f"add ntp server secondary 10.100.{node.site}.41 version 4",
            "set ntp active on",
        ]

    lines += ["", ""]
    return "\n".join(lines)


# ───────────────────────── Check Point management ────────────────────────────


def checkpoint_mgmt(node: Node) -> str:
    """A management server's policy bundle, as the API returns it.

    No interfaces and no routes: a management server holds the rulebase and forwards
    nothing, which is why the planner never puts one in a path. What it *does* give the
    estate is a Check Point rulebase for the firewall analysis to read.
    """
    weak = node.hardening is Hardening.WEAK

    def rule(order: int, name: str, src: str, dst: str, service: str, action: str, **kw):
        body = {
            "uid": f"rule-{node.site}-{order}",
            "name": name,
            "rule-number": order,
            "enabled": kw.get("enabled", True),
            "source": [{"name": src, "type": "network"}],
            "destination": [{"name": dst, "type": "network"}],
            "service": [{"name": service, "type": "service-tcp"}],
            "action": {"name": action},
            "track": {"type": {"name": kw.get("track", "Log")}},
        }
        return body

    if weak:
        rules = [
            rule(1, "Block RDP", "Any", "Any", "RDP", "Drop"),
            rule(2, "Partner RDP", "Any", "Any", "RDP", "Accept"),
            rule(3, "Permit any", "Any", "Any", "Any", "Accept", track="None"),
            rule(4, "Old migration", "Any", "Any", "Any", "Accept", enabled=False),
        ]
    else:
        rules = [
            rule(1, "Inbound web", "Any", "site-net", "https", "Accept"),
            rule(2, "Outbound", "site-net", "Any", "Any", "Accept"),
            rule(3, "Cleanup", "Any", "Any", "Any", "Drop"),
        ]

    bundle = {
        "show-access-rulebase": {
            "name": f"{node.hostname}-policy",
            "rulebase": rules,
            "total": len(rules),
            "to": len(rules),
        },
        "show-nat-rulebase": {
            "rulebase": [
                {
                    "uid": f"nat-{node.site}-1",
                    "name": "Hide site behind gateway",
                    "rule-number": 1,
                    "original-source": [{"name": "site-net"}],
                    "original-destination": [{"name": "Any"}],
                    "original-service": [{"name": "Any"}],
                    "translated-source": [{"name": "gateway-external"}],
                }
            ],
            "total": 1,
        },
        "show-gateways-and-servers": {
            "objects": [
                {
                    "uid": f"gw-{node.site}",
                    "name": f"{node.hostname}",
                    "type": "CpmiHostCkp",
                    "ipv4-address": node.mgmt_ip,
                    "version": "R81.20",
                }
            ]
        },
        "show-administrators": {
            "objects": [
                {
                    "uid": f"admin-{node.site}",
                    "name": "admin",
                    "authentication-method": "check point password" if weak else "radius",
                    "must-change-password": False,
                }
            ]
        },
    }
    return json.dumps(bundle, indent=2)


RENDERERS = {
    "cisco_ios": cisco_ios,
    "cisco_nxos": cisco_nxos,
    "cisco_asa": cisco_asa,
    "fortios": fortios,
    "panos": panos,
    "checkpoint_gaia": checkpoint_gaia,
    "checkpoint_mgmt": checkpoint_mgmt,
}


def render(node: Node) -> str:
    renderer = RENDERERS.get(node.platform)
    if renderer is None:  # pragma: no cover - the planner only emits known platforms
        raise ValueError(f"no renderer for platform {node.platform!r}")
    return renderer(node)
