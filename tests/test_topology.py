import pytest

from app import demo, topology
from app.mikrotik import error_snapshot, parse, parse_duration


@pytest.fixture(scope="module")
def snaps():
    out = []
    for r in demo.ROUTERS:
        try:
            out.append(parse(r, demo.raw_for(r.name)))
        except TimeoutError as e:
            out.append(error_snapshot(r, e))
    return out


@pytest.fixture(scope="module")
def graph(snaps):
    return topology.build(snaps)


def _edge(graph, kind, a, b):
    return next((e for e in graph["edges"] if e["kind"] == kind and {e["source"], e["target"]} == {a, b}), None)


def test_duration():
    assert parse_duration("1m5s") == 65
    assert parse_duration("1d00:01:05") == 86465
    assert parse_duration("") is None


def test_v6_routes_parsed(snaps):
    b2 = next(s for s in snaps if s["name"] == "branch2")
    r = next(r for r in b2["routes"] if r["dst"] == "192.168.20.0/24" and r["active"])
    assert r["hops"] == [{"gateway": "10.98.0.1", "interface": "gre-branch1", "vpn": "gre"}]


def test_tunnels_paired(graph):
    wg = _edge(graph, "tunnel", "r:hq", "r:branch1")
    assert wg and wg["vpn"] == "wireguard" and wg["state"] == "up"
    l2tp = _edge(graph, "tunnel", "r:hq", "r:branch2")
    assert l2tp and l2tp["vpn"] == "l2tp" and l2tp["ipsec"]
    assert _edge(graph, "tunnel", "r:branch1", "r:branch2")["vpn"] == "gre"
    assert _edge(graph, "tunnel", "r:hq", "peer:100.64.12.7")["state"] == "idle"
    assert _edge(graph, "tunnel", "r:hq", "peer:vpn.example.net")["state"] == "down"


def test_ipsec_policy_network(graph):
    assert _edge(graph, "route", "peer:192.0.2.50", "n:172.16.0.0/16")
    assert not _edge(graph, "route", "r:hq", "n:172.16.0.0/16")  # транзит branch1 → hq не рисуем отдельно


def test_unreachable_router(graph):
    dc = next(n for n in graph["nodes"] if n["id"] == "r:dc")
    assert dc["ok"] is False and dc["error"]


def test_trace_over_l2tp(snaps):
    tr = topology.trace(snaps, "hq", "192.168.30.15")
    assert tr["ok"] and tr["path"] == ["r:hq", "r:branch2", "n:192.168.30.0/24"]


def test_trace_policy_routing(snaps):
    tr = topology.trace(snaps, "hq", "8.8.8.8", src="192.168.10.200")
    assert tr["path"][:2] == ["r:hq", "r:branch1"] and tr["path"][-1] == "internet"
    tr = topology.trace(snaps, "hq", "8.8.8.8", src="192.168.10.20")
    assert tr["path"] == ["r:hq", "n:203.0.113.8/29", "gw:203.0.113.9", "internet"]


def test_trace_ipsec_needs_matching_src(snaps):
    tr = topology.trace(snaps, "hq", "172.16.5.5", src="192.168.10.7")
    assert tr["path"][-2:] == ["peer:192.0.2.50", "n:172.16.0.0/16"]
    tr = topology.trace(snaps, "hq", "172.16.5.5", src="192.168.99.7")  # не из src политики
    assert "peer:192.0.2.50" not in tr["path"]


def test_trace_wg_then_ipsec(snaps):
    tr = topology.trace(snaps, "branch1", "172.16.5.5", src="192.168.10.7")
    assert tr["path"] == ["r:branch1", "r:hq", "peer:192.0.2.50", "n:172.16.0.0/16"]
    assert len(tr["tunnel_edges"]) == 2


def test_trace_blackhole(snaps):
    tr = topology.trace(snaps, "hq", "10.200.1.1")  # OpenVPN лежит → маршрут неактивен → blackhole 10/8
    assert not tr["ok"] and tr["steps"][-1]["action"] == "blackhole"


def test_nat_parsed(snaps):
    hq = next(s for s in snaps if s["name"] == "hq")
    assert [r["action"] for r in hq["nat"]] == ["src-nat", "masquerade"]  # dstnat отброшен
    assert hq["nat"][1]["out_list"] == "WAN" and hq["iface_lists"]["WAN"] == ["ether1-wan"]
    assert hq["nat"][0]["extra"] == {"protocol": "tcp", "src-port": "25"}
    b1 = next(s for s in snaps if s["name"] == "branch1")
    assert b1["nat"][1]["dst"] == "192.168.0.0/16" and b1["nat"][1]["dst_neg"]


def _nat_texts(tr):
    return [st["text"] for st in tr["steps"] if st["action"] == "nat"]


def test_trace_masquerade(snaps):
    tr = topology.trace(snaps, "hq", "8.8.8.8", src="192.168.10.20")
    assert _nat_texts(tr)[0].startswith("srcnat: 192.168.10.20 → 203.0.113.10 (masquerade")
    assert tr["src"] == "203.0.113.10"


def test_trace_ipsec_policy_none_skips_masquerade(snaps):
    tr = topology.trace(snaps, "hq", "172.16.5.5", src="192.168.10.7")
    assert not _nat_texts(tr) and tr["src"] == "192.168.10.7"
    assert tr["steps"][-1]["action"] == "ipsec"


def test_trace_srcnat_before_ipsec(snaps):
    # branch1 транслирует 192.168.20.x в 192.168.10.250 → на HQ срабатывает политика 192.168.10.0/24
    tr = topology.trace(snaps, "branch1", "172.16.5.5", src="192.168.20.5")
    assert _nat_texts(tr)[0].startswith("srcnat: 192.168.20.5 → 192.168.10.250")
    assert tr["path"] == ["r:branch1", "r:hq", "peer:192.0.2.50", "n:172.16.0.0/16"]


def test_trace_ipsec_miss_explained(snaps):
    tr = topology.trace(snaps, "hq", "172.16.5.5", src="192.168.99.7")
    assert any("не сработала: источник 203.0.113.10 не из 192.168.10.0/24" in st["text"] for st in tr["steps"])


def test_trace_src_defaults_to_egress(snaps):
    tr = topology.trace(snaps, "hq", "172.16.5.5")
    assert any("берём адрес роутера на ether1-wan: 203.0.113.10" in st["text"] for st in tr["steps"])
    assert "peer:192.0.2.50" not in tr["path"]


def test_trace_netmap(snaps):
    tr = topology.trace(snaps, "branch2", "192.168.10.9", src="192.168.31.77")
    assert _nat_texts(tr)[0].startswith("srcnat: 192.168.31.77 → 10.31.0.77 (netmap")
    assert tr["path"][:2] == ["r:branch2", "r:hq"]


def test_trace_unsupported_nat_noted(snaps):
    tr = topology.trace(snaps, "hq", "8.8.8.8", src="192.168.10.5")
    assert any(st["action"] == "info" and "protocol=tcp" in st["text"] for st in tr["steps"])
    assert _nat_texts(tr)[0].startswith("srcnat: 192.168.10.5 → 203.0.113.10")
