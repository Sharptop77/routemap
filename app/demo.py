"""Демо-стенд: три роутера и один недоступный. Данные в "сыром" формате RouterOS
(как отдаёт REST v7 / API v6), чтобы через демо проходил тот же парсер, что и в бою.

  HQ (v7) ══WireGuard══ Branch1 (v7)
   ║  ╲                    ║ GRE (резерв)
   ║   L2TP+IPsec ════ Branch2 (v6, классический API)
   ╠══ IPsec site-to-site → партнёр 192.0.2.50 (172.16.0.0/16)
   ╠══ OpenVPN → vpn.example.net (лежит)
   ╚══ WireGuard road-warrior
"""
from .mikrotik import RouterConfig

ROUTERS = [
    RouterConfig(name="hq", host="203.0.113.10", transport="rest", demo=True),
    RouterConfig(name="branch1", host="198.51.100.20", transport="rest", demo=True),
    RouterConfig(name="branch2", host="192.0.2.30", transport="api", demo=True),
    RouterConfig(name="dc", host="10.50.0.1", transport="api-ssl", demo=True),
]


def _ifc(name, type_, running=True, **kw):
    return {"name": name, "type": type_, "running": "true" if running else "false", "disabled": "false", **kw}


def _addr(address, iface, network=None, dynamic=False):
    d = {"address": address, "interface": iface, "disabled": "false", "dynamic": str(dynamic).lower()}
    if network:
        d["network"] = network
    return d


def _nat(i, action, **kw):
    return {".id": f"*{i}", "chain": "srcnat", "action": action, "disabled": "false",
            **{k.replace("_", "-"): v for k, v in kw.items()}}


def _r7(i, dst, gw, imm=None, proto="static", active=True, distance=1, table="main", **kw):
    d = {".id": f"*{i}", "dst-address": dst, "gateway": gw, "distance": str(distance),
         "active": str(active).lower(), "routing-table": table, proto: "true", **kw}
    if imm:
        d["immediate-gw"] = imm
    if proto != "static":
        d["dynamic"] = "true"
    return d


def _r6(i, dst, gw, status, proto="static", active=True, distance=1, **kw):
    d = {".id": f"*{i}", "dst-address": dst, "gateway": gw, "gateway-status": status,
         "distance": str(distance), "active": str(active).lower(), proto: "true", **kw}
    if proto != "static":
        d["dynamic"] = "true"
    return d


HQ = {
    "identity": [{"name": "HQ-CCR2004"}],
    "resource": [{"version": "7.16.1 (stable)", "board-name": "CCR2004-16G-2S+", "uptime": "21d4h"}],
    "interfaces": [
        _ifc("ether1-wan", "ether"), _ifc("bridge-lan", "bridge"), _ifc("wg-hub", "wg"),
        _ifc("<l2tp-branch2>", "l2tp-in", dynamic="true"), _ifc("ovpn-cloud", "ovpn-out", running=False),
    ],
    "addresses": [
        _addr("203.0.113.10/29", "ether1-wan", "203.0.113.8"),
        _addr("192.168.10.1/24", "bridge-lan", "192.168.10.0"),
        _addr("10.99.0.1/24", "wg-hub", "10.99.0.0"),
        _addr("10.10.10.1/32", "<l2tp-branch2>", "10.10.10.2", dynamic=True),
    ],
    "routes": [
        _r7(1, "0.0.0.0/0", "203.0.113.9", "203.0.113.9%ether1-wan"),
        _r7(2, "0.0.0.0/0", "10.99.0.2", "10.99.0.2%wg-hub", table="via-branch1", comment="LAN .128/25 в интернет через Branch1"),
        _r7(3, "192.168.20.0/24", "10.99.0.2", "10.99.0.2%wg-hub"),
        _r7(4, "192.168.30.0/24", "10.10.10.2", "10.10.10.2%<l2tp-branch2>", proto="ospf", distance=110),
        _r7(5, "192.168.31.0/24", "10.10.10.2", "10.10.10.2%<l2tp-branch2>", proto="ospf", distance=110),
        _r7(6, "10.200.0.0/16", "ovpn-cloud", active=False, comment="облако, через OpenVPN"),
        _r7(7, "10.0.0.0/8", "", proto="blackhole", distance=250, blackhole="true"),
        _r7(8, "203.0.113.8/29", "ether1-wan", "ether1-wan", proto="connect", distance=0),
        _r7(9, "192.168.10.0/24", "bridge-lan", "bridge-lan", proto="connect", distance=0),
        _r7(10, "10.99.0.0/24", "wg-hub", "wg-hub", proto="connect", distance=0),
    ],
    "wg": [{"name": "wg-hub", "listen-port": "13231"}],
    "wg_peers": [
        {".id": "*1", "interface": "wg-hub", "name": "branch1", "endpoint-address": "198.51.100.20",
         "endpoint-port": "13231", "current-endpoint-address": "198.51.100.20", "current-endpoint-port": "13231",
         "allowed-address": "10.99.0.2/32,192.168.20.0/24", "last-handshake": "38s", "rx": "1843920113", "tx": "932111840"},
        {".id": "*2", "interface": "wg-hub", "name": "roadwarrior-1", "current-endpoint-address": "100.64.12.7",
         "current-endpoint-port": "51820", "allowed-address": "10.99.0.50/32", "last-handshake": "7m12s",
         "rx": "18310112", "tx": "73402213"},
    ],
    "ipsec_peers": [{"name": "partner-dc", "address": "192.0.2.50/32", "local-address": "203.0.113.10"}],
    "ipsec_active": [
        {"remote-address": "192.0.2.50", "state": "established", "uptime": "3h12m"},
        {"remote-address": "192.0.2.30", "state": "established", "uptime": "2d4h"},
    ],
    "ipsec_policies": [
        {".id": "*0", "src-address": "::/0", "dst-address": "::/0", "template": "true", "group": "default"},
        {".id": "*1", "src-address": "192.168.10.0/24", "dst-address": "172.16.0.0/16", "tunnel": "true",
         "peer": "partner-dc", "sa-src-address": "203.0.113.10", "sa-dst-address": "192.0.2.50",
         "action": "encrypt", "ph2-state": "established", "active": "true"},
        {".id": "*2", "src-address": "203.0.113.10/32", "dst-address": "192.0.2.30/32", "tunnel": "false",
         "dynamic": "true", "action": "encrypt", "ph2-state": "established", "protocol": "udp"},
    ],
    "ovpn_client": [{"name": "ovpn-cloud", "connect-to": "vpn.example.net", "user": "hq", "running": "false"}],
    "l2tp_client": [], "sstp_client": [], "pptp_client": [], "gre": [], "ipip": [], "eoip": [],
    "ppp_active": [{"name": "branch2", "service": "l2tp", "caller-id": "192.0.2.30", "address": "10.10.10.2",
                    "uptime": "2d4h11m"}],
    "rules7": [{"src-address": "192.168.10.128/25", "action": "lookup", "table": "via-branch1",
                "comment": "гостевая половина LAN — через Branch1"}],
    "rules6": [],
    "nat": [
        _nat(2, "src-nat", to_addresses="203.0.113.11", protocol="tcp", src_address="192.168.10.5",
             src_port="25", comment="почта с отдельного IP"),
        _nat(1, "masquerade", out_interface_list="WAN", ipsec_policy="out,none", comment="defconf: masquerade"),
        {"chain": "dstnat", "action": "dst-nat", "dst-port": "443", "protocol": "tcp", "to-addresses": "192.168.10.5"},
    ],
    "iface_lists": [{"list": "WAN", "interface": "ether1-wan"}, {"list": "LAN", "interface": "bridge-lan"}],
}

BRANCH1 = {
    "identity": [{"name": "Branch1-RB5009"}],
    "resource": [{"version": "7.15.3 (stable)", "board-name": "RB5009UG+S+", "uptime": "9d2h"}],
    "interfaces": [_ifc("ether1", "ether"), _ifc("bridge-lan", "bridge"), _ifc("wg-hq", "wg"),
                   _ifc("gre-branch2", "gre-tunnel")],
    "addresses": [
        _addr("198.51.100.20/30", "ether1", "198.51.100.20"),
        _addr("192.168.20.1/24", "bridge-lan", "192.168.20.0"),
        _addr("10.99.0.2/24", "wg-hq", "10.99.0.0"),
        _addr("10.98.0.1/30", "gre-branch2", "10.98.0.0"),
    ],
    "routes": [
        _r7(1, "0.0.0.0/0", "198.51.100.21", "198.51.100.21%ether1"),
        _r7(2, "192.168.10.0/24", "10.99.0.1", "10.99.0.1%wg-hq"),
        _r7(3, "172.16.0.0/16", "10.99.0.1", "10.99.0.1%wg-hq", comment="партнёр через HQ"),
        _r7(4, "192.168.30.0/24", "10.99.0.1", "10.99.0.1%wg-hq"),
        _r7(5, "192.168.30.0/24", "10.98.0.2", "10.98.0.2%gre-branch2", active=False, distance=5, comment="резерв"),
        _r7(6, "192.168.20.0/24", "bridge-lan", "bridge-lan", proto="connect", distance=0),
    ],
    "wg": [{"name": "wg-hq"}],
    "wg_peers": [
        {".id": "*1", "interface": "wg-hq", "name": "hq", "endpoint-address": "203.0.113.10", "endpoint-port": "13231",
         "current-endpoint-address": "203.0.113.10", "current-endpoint-port": "13231",
         "allowed-address": "10.99.0.0/24,192.168.10.0/24,192.168.30.0/24,172.16.0.0/16,0.0.0.0/0",
         "last-handshake": "41s", "persistent-keepalive": "25s", "rx": "932100211", "tx": "1843911022"},
    ],
    "gre": [{"name": "gre-branch2", "local-address": "198.51.100.20", "remote-address": "192.0.2.30",
             "running": "true", "keepalive": "10s,10"}],
    "ipsec_peers": [], "ipsec_active": [], "ipsec_policies": [], "ovpn_client": [], "l2tp_client": [],
    "sstp_client": [], "pptp_client": [], "ipip": [], "eoip": [], "ppp_active": [], "rules7": [], "rules6": [],
    "nat": [
        _nat(1, "src-nat", src_address="192.168.20.0/24", dst_address="172.16.0.0/16", to_addresses="192.168.10.250",
             comment="партнёр пускает только из 192.168.10.0/24 — маскируемся адресом HQ"),
        _nat(2, "masquerade", out_interface="ether1", dst_address="!192.168.0.0/16"),
    ],
    "iface_lists": [],
}

# RouterOS 6 через классический API: gateway-status вместо immediate-gw, без WireGuard
BRANCH2 = {
    "identity": [{"name": "Branch2-hEX"}],
    "resource": [{"version": "6.49.15 (long-term)", "board-name": "hEX", "uptime": "48d"}],
    "interfaces": [_ifc("ether1", "ether"), _ifc("bridge-lan", "bridge"), _ifc("bridge-guest", "bridge"),
                   _ifc("l2tp-hq", "l2tp-out"), _ifc("gre-branch1", "gre-tunnel")],
    "addresses": [
        _addr("192.0.2.30/29", "ether1", "192.0.2.24"),
        _addr("192.168.30.1/24", "bridge-lan", "192.168.30.0"),
        _addr("192.168.31.1/24", "bridge-guest", "192.168.31.0"),
        _addr("10.10.10.2/32", "l2tp-hq", "10.10.10.1", dynamic=True),
        _addr("10.98.0.2/30", "gre-branch1", "10.98.0.0"),
    ],
    "routes": [
        _r6(1, "0.0.0.0/0", "192.0.2.25", "192.0.2.25 reachable via  ether1"),
        _r6(2, "192.168.10.0/24", "10.10.10.1", "10.10.10.1 reachable via  l2tp-hq", proto="ospf", distance=110),
        _r6(3, "10.99.0.0/24", "10.10.10.1", "10.10.10.1 reachable via  l2tp-hq", proto="ospf", distance=110),
        _r6(4, "192.168.20.0/24", "10.98.0.1", "10.98.0.1 reachable via  gre-branch1"),
        _r6(5, "192.168.20.0/24", "10.10.10.1", "10.10.10.1 reachable via  l2tp-hq", proto="ospf",
            distance=110, active=False),
        _r6(6, "192.168.30.0/24", "bridge-lan", "bridge-lan reachable", proto="connect", distance=0),
    ],
    "l2tp_client": [{"name": "l2tp-hq", "connect-to": "203.0.113.10", "user": "branch2", "use-ipsec": "true",
                     "running": "true"}],
    "gre": [{"name": "gre-branch1", "local-address": "192.0.2.30", "remote-address": "198.51.100.20",
             "running": "true"}],
    "ipsec_active": [{"remote-address": "203.0.113.10", "state": "established"}],
    "ipsec_peers": [], "ipsec_policies": [], "wg": [], "wg_peers": [], "ovpn_client": [], "sstp_client": [],
    "pptp_client": [], "ipip": [], "eoip": [], "ppp_active": [], "rules7": [], "rules6": [],
    "nat": [
        _nat(1, "netmap", src_address="192.168.31.0/24", dst_address="192.168.10.0/24", out_interface="l2tp-hq",
             to_addresses="10.31.0.0/24", comment="гостевая сеть в HQ — под своим диапазоном"),
        _nat(2, "masquerade", out_interface="ether1"),
    ],
    "iface_lists": [],
    "_errors": {"wg": "no such command prefix", "wg_peers": "no such command prefix",
                "rules7": "no such command prefix"},
}

RAW = {"hq": HQ, "branch1": BRANCH1, "branch2": BRANCH2}


def raw_for(name: str) -> dict:
    if name not in RAW:
        raise TimeoutError("timed out (демо: роутер недоступен)")
    return RAW[name]
