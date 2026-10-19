"""Парсер OPNsense на синтетических данных в формате реального API (24.x–25.x)."""
import time

from app import opnsense, topology
from app.mikrotik import RouterConfig

RAW = {
    "_errors": {"ovpn_sessions": "HTTP 403"},
    "routes": [
        {"proto": "ipv4", "destination": "default", "gateway": "192.0.2.1", "flags": "UGS", "netif": "re1"},
        {"proto": "ipv4", "destination": "192.0.2.0/24", "gateway": "link#2", "flags": "U", "netif": "re1"},
        {"proto": "ipv4", "destination": "10.1.0.0/24", "gateway": "link#1", "flags": "U", "netif": "re0"},
        {"proto": "ipv4", "destination": "10.1.0.1", "gateway": "link#3", "flags": "UHS", "netif": "lo0"},
        {"proto": "ipv4", "destination": "10.9.0.0/24", "gateway": "10.8.0.1", "flags": "UGS", "netif": "ovpnc2"},
        {"proto": "ipv4", "destination": "10.8.0.1", "gateway": "link#8", "flags": "UH", "netif": "ovpnc2"},
        {"proto": "ipv4", "destination": "10.50.0.0/16", "gateway": "10.7.0.2", "flags": "UG1", "netif": "wg0"},
        {"proto": "ipv6", "destination": "::1", "gateway": "link#3", "flags": "UHS", "netif": "lo0"},
    ],
    "interfaces": [
        {"device": "re0", "description": "LAN", "identifier": "lan", "status": "up", "enabled": True,
         "ipv4": [{"ipaddr": "10.1.0.1/24"}]},
        {"device": "re1", "description": "WAN", "identifier": "wan", "status": "up", "enabled": True,
         "link_type": "dhcp", "ipv4": [{"ipaddr": "192.0.2.10/24"}]},
        {"device": "ovpnc2", "description": "Unassigned Interface", "identifier": "", "status": "up",
         "ipv4": [{"ipaddr": "10.8.0.2", "subnetbits": 32, "tunnel": True, "endpoint": "10.8.0.1"}]},
        {"device": "wg0", "description": "WG", "identifier": "opt1", "status": "up", "enabled": True,
         "ipv4": [{"ipaddr": "10.7.0.1/24"}]},
    ],
    "wg_show": {"rows": [
        {"if": "wg0", "type": "interface"},
        {"if": "wg0", "type": "peer", "name": "site-b", "public-key": "AAAABBBBCCCCDDDD",
         "endpoint": "198.51.100.7:51820", "allowed-ips": "10.7.0.2/32,10.50.0.0/16",
         "latest-handshake": str(int(time.time()) - 30)},
        {"if": "wg0", "type": "peer", "name": "laptop", "public-key": "EEEEFFFF", "endpoint": "(none)",
         "allowed-ips": "10.7.0.9/32", "latest-handshake": "0"},
    ]},
    "nat": {"rows": [
        {"uuid": "a1", "enabled": "1", "interface": "wan", "source_net": "lan,lo0", "destination_port": "500",
         "is_automatic": True, "description": "Auto created rule for ISAKMP"},
        {"uuid": "a2", "enabled": "1", "interface": "wan", "source_net": "lan,lo0,127.0.0.0/8",
         "is_automatic": True, "description": "Auto created rule"},
    ]},
}


def snap():
    return opnsense.parse(RouterConfig(name="opn", host="10.1.0.1", transport="opnsense"), RAW)


def test_routes_and_interfaces():
    s = snap()
    by = {r["dst"]: r for r in s["routes"]}
    assert by["0.0.0.0/0"]["protocol"] == "static"
    assert by["10.1.0.0/24"]["protocol"] == "connected"
    assert by["10.50.0.0/16"]["protocol"] == "dynamic"  # флаг 1 — FRR
    assert "10.1.0.1/32" not in by  # lo0 пропущен
    a = next(a for a in s["addresses"] if a["interface"] == "ovpnc2")
    assert (a["ip"], a["prefix"], a["peer"]) == ("10.8.0.2", 32, "10.8.0.1")
    assert any("403" in w for w in s["warnings"])


def test_tunnels():
    t = {x["label"]: x for x in snap()["tunnels"]}
    assert t["site-b"]["state"] == "up" and t["site-b"]["remote_public"] == "198.51.100.7"
    assert t["laptop"]["state"] == "down"
    assert t["ovpnc2"]["kind"] == "ovpn-client" and t["ovpnc2"]["state"] == "up"


def test_nat_and_trace():
    s = snap()
    assert all(r["comment"] != "Auto created rule for ISAKMP" for r in s["nat"])
    tr = topology.trace([s], "opn", "8.8.8.8", src="10.1.0.50")
    assert tr["path"][-1] == "internet"
    assert any("10.1.0.50 → 192.0.2.10" in st["text"] for st in tr["steps"])
    tr = topology.trace([s], "opn", "10.50.1.1", src="10.1.0.50")  # WireGuard peer по allowed-ips
    assert tr["tunnel_edges"] and "site-b" in tr["steps"][-1]["text"]
