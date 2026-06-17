"""Tier 1 network-collector parsers + wiring.

macOS samples are real output captured from this platform; Linux/Windows
samples are representative of the documented formats.
"""

from __future__ import annotations

from avai.enrichers import IndicatorType, extract_indicators
from avai.host_monitor.hosts.linux import LinuxHost
from avai.host_monitor.hosts.macos import MacOSHost
from avai.host_monitor.hosts.windows import WindowsHost
from avai.host_monitor.net_collectors import (
    IpNeighParser,
    IpRouteParser,
    MacosArpParser,
    MacosDnsParser,
    MacosNdpParser,
    MacosRouteParser,
    PsDnsParser,
    PsNeighborParser,
    PsRouteParser,
    ResolvConfParser,
)
from avai.host_monitor.prompts import Prompts

_P = Prompts(system="", user_template="")


# ---- macOS (validated against real output) -------------------------------

_ARP = """\
? (192.168.1.1) at 74:24:9f:e8:d2:23 on en6 ifscope [ethernet]
? (192.168.1.62) at (incomplete) on en6 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en6 ifscope permanent [ethernet]
"""


class TestMacosArpParser:
    def test_parses_gateway_and_incomplete(self):
        rows = MacosArpParser().parse(_ARP)
        assert rows[0] == {
            "ip": "192.168.1.1",
            "mac": "74:24:9f:e8:d2:23",
            "interface": "en6",
            "flags": "ifscope",
            "raw_json": rows[0]["raw_json"],
        }
        assert rows[1]["mac"] is None  # (incomplete)
        assert rows[2]["flags"] == "ifscope permanent"


_NDP = """\
Neighbor                                Linklayer Address  Netif Expire    St Flgs Prbs
2803:9810:469f:7108:1007:4426:2f0d:e593 34:29:8f:72:3b:3a    en6 permanent R
2803:9810:469f:7108:c1df:cf83:2d4:b459  (incomplete)         en6 expired   N
"""


class TestMacosNdpParser:
    def test_parses_state_and_incomplete(self):
        rows = MacosNdpParser().parse(_NDP)
        assert rows[0]["ip"].startswith("2803:")
        assert rows[0]["mac"] == "34:29:8f:72:3b:3a"
        assert rows[0]["interface"] == "en6"
        assert rows[0]["state"] == "R"
        assert rows[1]["mac"] is None


_ROUTES = """\
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en6
127                127.0.0.1          UCS                   lo0
192.168.1.1        74:24:9f:e8:d2:23  UHLWIir               en6   1170
link#13            link#13            UCS                   en6
"""


class TestMacosRouteParser:
    def test_keeps_default_drops_neighbor_and_link(self):
        rows = MacosRouteParser().parse(_ROUTES)
        dests = [r["destination"] for r in rows]
        assert "default" in dests
        assert "127" in dests  # 127.0.0.1 is an IP gateway → kept
        # MAC-gateway (neighbor) and link# rows are dropped
        assert "192.168.1.1" not in dests
        default = next(r for r in rows if r["destination"] == "default")
        assert default["gateway"] == "192.168.1.1"
        assert default["interface"] == "en6"


_SCUTIL = """\
DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : 8.8.8.8
  if_index : 13 (en6)

resolver #2
  domain   : local
  options  : mdns
"""


class TestMacosDnsParser:
    def test_one_row_per_nameserver_with_iface(self):
        rows = MacosDnsParser().parse(_SCUTIL)
        assert [r["server"] for r in rows] == ["192.168.1.1", "8.8.8.8"]
        assert all(r["interface"] == "en6" for r in rows)
        assert rows[0]["search"] == "lan"


# ---- Linux ----------------------------------------------------------------


class TestIpNeighParser:
    def test_arp_flags_key_and_missing_lladdr(self):
        text = (
            "192.168.1.1 dev eth0 lladdr 74:24:9f:e8:d2:23 REACHABLE\n"
            "10.0.0.9 dev eth0 FAILED\n"
        )
        rows = IpNeighParser("flags").parse(text)
        assert rows[0] == {
            "ip": "192.168.1.1",
            "mac": "74:24:9f:e8:d2:23",
            "interface": "eth0",
            "flags": "REACHABLE",
            "raw_json": rows[0]["raw_json"],
        }
        assert rows[1]["mac"] is None and rows[1]["flags"] == "FAILED"

    def test_ndp_uses_state_key(self):
        rows = IpNeighParser("state").parse(
            "fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE\n"
        )
        assert rows[0]["state"] == "STALE"
        assert "flags" not in rows[0]


class TestIpRouteParser:
    def test_keeps_default_and_via_routes(self):
        text = (
            "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n"
            "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.50\n"
        )
        rows = IpRouteParser().parse(text)
        assert len(rows) == 1  # link route (no via) dropped
        assert rows[0]["destination"] == "default"
        assert rows[0]["gateway"] == "192.168.1.1"
        assert rows[0]["flags"] == "dhcp"


class TestResolvConfParser:
    def test_nameservers_and_search(self):
        rows = ResolvConfParser().parse(
            "# comment\nsearch lan corp\nnameserver 1.1.1.1\nnameserver 8.8.4.4\n"
        )
        assert [r["server"] for r in rows] == ["1.1.1.1", "8.8.4.4"]
        assert rows[0]["search"] == "lan corp"
        assert rows[0]["scope"] == "resolv.conf"


# ---- Windows (PowerShell JSON) --------------------------------------------


class TestPsParsers:
    def test_neighbor_array_and_state_key(self):
        text = (
            '[{"IPAddress":"192.168.1.1","LinkLayerAddress":"74-24-9F-E8-D2-23",'
            '"InterfaceAlias":"Ethernet","State":"Reachable"}]'
        )
        rows = PsNeighborParser("flags").parse(text)
        assert rows[0]["ip"] == "192.168.1.1"
        assert rows[0]["mac"] == "74-24-9F-E8-D2-23"
        assert rows[0]["flags"] == "Reachable"

    def test_route_keeps_default_and_nexthop(self):
        text = (
            '[{"DestinationPrefix":"0.0.0.0/0","NextHop":"192.168.1.1",'
            '"InterfaceAlias":"Ethernet","RouteMetric":0},'
            '{"DestinationPrefix":"192.168.1.0/24","NextHop":"0.0.0.0",'
            '"InterfaceAlias":"Ethernet","RouteMetric":256}]'
        )
        rows = PsRouteParser().parse(text)
        assert [r["destination"] for r in rows] == ["0.0.0.0/0"]

    def test_dns_one_row_per_server(self):
        text = '{"InterfaceAlias":"Ethernet","ServerAddresses":["8.8.8.8","8.8.4.4"]}'
        rows = PsDnsParser().parse(text)
        assert [r["server"] for r in rows] == ["8.8.8.8", "8.8.4.4"]

    def test_empty_json_is_empty(self):
        assert PsRouteParser().parse("") == []
        assert PsNeighborParser("flags").parse("null") == []


# ---- enrichment + wiring --------------------------------------------------


class TestDnsResolverEnrichment:
    def test_public_server_emits_indicator(self):
        inds = extract_indicators("dns_resolvers", {"server": "8.8.8.8"})
        assert inds and inds[0].type == IndicatorType.IPV4

    def test_private_server_is_not_enriched(self):
        assert extract_indicators("dns_resolvers", {"server": "192.168.1.1"}) == []

    def test_arp_table_has_no_extractor(self):
        # LAN MACs/IPs aren't threat-intel material → NoOp.
        assert extract_indicators("arp_table", {"ip": "192.168.1.1"}) == []


class TestWiring:
    def test_each_host_assembles_tier1(self):
        for host in (MacOSHost(), LinuxHost(), WindowsHost()):
            names = {c.name for c in host.snapshot_collectors(_P)}
            assert {"arp_table", "ndp_neighbors", "routes", "dns_resolvers"} <= names
