"""Построение графа маршрутов из снимков роутеров + трассировка пути до адреса.

Узлы:   r:<router>   — маршрутизатор
        n:<cidr>     — сеть (подключённая или удалённая, известная из маршрутов)
        gw:<ip>      — внешний шлюз (не наш роутер), например шлюз провайдера
        peer:<host>  — удалённая сторона VPN, которую мы не опрашиваем
        internet     — 0.0.0.0/0
Рёбра:  connected (роутер—сеть), lan (сеть—шлюз), tunnel (VPN), route (решение маршрутизации).
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict

from .mikrotik import find_connected

KIND_LABELS = {
    "wireguard": "WireGuard", "ipsec": "IPsec", "l2tp": "L2TP", "ovpn": "OpenVPN", "sstp": "SSTP",
    "pptp": "PPTP", "gre": "GRE", "ipip": "IPIP", "eoip": "EoIP", "vxlan": "VXLAN", "zerotier": "ZeroTier",
}
ALL_PROTOCOLS = ("static", "ospf", "bgp", "rip", "dynamic", "blackhole", "ipsec")
MATCH_THRESHOLD = 10


def _net(s):
    return ipaddress.ip_network(s, strict=False)


def _in(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in _net(cidr)
    except ValueError:
        return False


def _subnet_of(a: str, b: str) -> bool:
    try:
        return _net(a).subnet_of(_net(b))
    except (ValueError, TypeError):
        return False


def dst_node(cidr: str) -> str:
    return "internet" if cidr == "0.0.0.0/0" else f"n:{cidr}"


# ---------------------------------------------------------------- контекст

class Context:
    """Индексы поверх всех снимков: владельцы IP, сопоставленные туннели."""

    def __init__(self, snaps: list[dict]):
        self.snaps = {s["name"]: s for s in snaps}
        self.ok = {n: s for n, s in self.snaps.items() if s["ok"]}
        self.ip_owner: dict[str, str] = {}
        for s in self.ok.values():
            for ip in s["ips"]:
                self.ip_owner.setdefault(ip, s["name"])
        self.tunnels = [t for s in self.ok.values() for t in s["tunnels"]]
        self.by_iface: dict[tuple, list] = defaultdict(list)
        for t in self.tunnels:
            if t["interface"]:
                self.by_iface[(t["router"], t["interface"])].append(t)
        self._match_tunnels()

    def _score(self, a: dict, b: dict) -> int:
        def best(nets, ips):
            return max((int(n.split("/")[1]) for n in nets for ip in ips if _in(ip, n)), default=0)

        c1, c2 = best(b["remote_nets"], a["local_ips"]), best(a["remote_nets"], b["local_ips"])
        # адреса — только взаимное совпадение: широкий allowed-address (192.168.0.0/16) у одной
        # стороны иначе "ловит" чужие туннели
        s = c1 + c2 if c1 and c2 else 0
        if not s and any(n in b["local_nets"] and int(n.split("/")[1]) >= 29 for n in a["local_nets"]):
            s += 20  # общая p2p-подсеть /29-/31 (GRE, IPIP)
        if a["remote_public"] and a["remote_public"] in self.snaps[b["router"]]["ips"]:
            s += 10
        if b["remote_public"] and b["remote_public"] in self.snaps[a["router"]]["ips"]:
            s += 10
        if s and a["kind"] == "eoip" and a["details"].get("tunnel-id") == b["details"].get("tunnel-id"):
            s += 5
        return s

    def _match_tunnels(self):
        """Жадно сопоставляем стороны одного туннеля на разных роутерах (лучший счёт — первым)."""
        cands = []
        for i, a in enumerate(self.tunnels):
            for b in self.tunnels[i + 1:]:
                if a["router"] == b["router"] or a["family"] != b["family"]:
                    continue
                sc = self._score(a, b)
                if sc >= MATCH_THRESHOLD:
                    cands.append((sc, a["uid"], b["uid"], a, b))
        cands.sort(key=lambda x: (-x[0], x[1], x[2]))
        pair = {}
        for _, _, _, a, b in cands:
            if a["uid"] in pair or b["uid"] in pair:
                continue
            pair[a["uid"]], pair[b["uid"]] = b, a
        for t in self.tunnels:
            other = pair.get(t["uid"])
            t["pair"] = other["uid"] if other else None
            if other:
                t["peer_router"] = other["router"]
                t["edge_id"] = "t:" + "|".join(sorted((t["uid"], other["uid"])))
            else:
                owner = self.ip_owner.get(t["remote_public"] or "")
                t["peer_router"] = owner if owner and owner != t["router"] else None
                t["edge_id"] = f"t:{t['uid']}"
            if t["peer_router"]:
                t["peer_node"] = f"r:{t['peer_router']}"
            else:
                key = t["remote_public"] or t["remote_host"] or f"{t['router']}:{t['id']}"
                t["peer_node"] = f"peer:{key}"

    def choose_tunnel(self, router: str, iface: str, gateway: str | None, dst: str | None) -> dict | None:
        cands = self.by_iface.get((router, iface)) or []
        if len(cands) <= 1:
            return cands[0] if cands else None
        # WireGuard (cryptokey routing): peer с самым специфичным allowed-address, покрывающим адрес
        # назначения пакета; шлюз маршрута роли не играет. Для IP-адреса dst передаётся как gateway.
        for target in (dst, gateway):
            if not target:
                continue
            best = None
            for t in cands:
                for n in t["routed_nets"] + t["remote_nets"]:
                    hit = _subnet_of(target, n) if "/" in target else _in(target, n)
                    plen = int(n.split("/")[1])
                    if hit and (best is None or plen > best[0]):
                        best = (plen, t)
            if best:
                return best[1]
        return cands[0]

    def resolve_hop(self, snap: dict, route: dict, hop: dict) -> dict:
        """Куда уходит маршрут: цепочка узлов графа после самого роутера."""
        R = snap["name"]
        if route["protocol"] == "blackhole":
            return {"via": "blackhole", "nodes": [], "tunnel": None, "next_router": None}
        iface, gw = hop.get("interface"), hop.get("gateway")
        if not iface and gw:
            a = find_connected(snap, gw)
            iface = a["interface"] if a else None
        if iface:
            t = self.choose_tunnel(R, iface, gw, route["dst"])
            if t:
                return {"via": "vpn", "nodes": [t["peer_node"]], "tunnel": t, "next_router": t["peer_router"]}
        if gw:
            a = find_connected(snap, gw, iface)
            lan = [f"n:{a['cidr']}"] if a and a["prefix"] < 32 else []
            owner = self.ip_owner.get(gw)
            if owner and owner != R:
                return {"via": "router", "nodes": lan + [f"r:{owner}"], "tunnel": None, "next_router": owner}
            return {"via": "gateway", "nodes": lan + [f"gw:{gw}"], "tunnel": None, "next_router": None}
        if iface:
            nets = [a for a in snap["addresses"] if a["interface"] == iface and a["prefix"] < 32]
            # на интерфейсе несколько сетей — неизвестно, через какую; рисуем от роутера
            return {"via": "interface", "nodes": [f"n:{nets[0]['cidr']}"] if len(nets) == 1 else [],
                    "tunnel": None, "next_router": None}
        return {"via": "unknown", "nodes": [], "tunnel": None, "next_router": None}

    def handles(self, router: str, cidr: str) -> bool:
        """Есть ли у роутера своё решение для сети (подключена или есть маршрут)."""
        s = self.ok.get(router)
        if not s:
            return False
        return any(a["cidr"] == cidr for a in s["addresses"] if a["prefix"] < 32) or \
            any(r["dst"] == cidr and r["active"] for r in s["routes"]) or \
            any(cidr in t["routed_nets"] for t in s["tunnels"] if t["kind"] == "ipsec")


# ---------------------------------------------------------------- граф

class Graph:
    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: dict[str, dict] = {}
        self.pairs: dict[frozenset, str] = {}

    def node(self, nid: str, **data) -> dict:
        if nid not in self.nodes:
            self.nodes[nid] = {"id": nid, **data}
        return self.nodes[nid]

    def edge(self, src: str, dst: str, kind: str, eid: str | None = None, index: bool = True, **data) -> dict:
        key = frozenset((src, dst))
        if index and key in self.pairs:
            return self.edges[self.pairs[key]]
        eid = eid or f"{kind}:{src}->{dst}"
        e = self.edges.setdefault(eid, {"id": eid, "source": src, "target": dst, "kind": kind, "routes": [], **data})
        if index:
            self.pairs[key] = eid
        return e

    def network(self, cidr: str, role: str = "remote") -> dict:
        if cidr == "0.0.0.0/0":
            return self.node("internet", kind="internet", label="Интернет")
        return self.node(f"n:{cidr}", kind="network", cidr=cidr, label=cidr, role=role, attached=[])


def _route_info(snap: dict, r: dict, hop: dict, res: dict) -> dict:
    t = res.get("tunnel")
    return {
        "router": snap["name"], "dst": r["dst"], "gateway": hop.get("gateway") or hop.get("interface") or "",
        "interface": hop.get("interface") or "", "protocol": r["protocol"], "table": r["table"],
        "distance": r["distance"], "active": r["active"], "via": res["via"],
        "tunnel": t["label"] if t else None, "vpn": t["family"] if t else None,
    }


def _add_route(g: Graph, ctx: Context, chain: list[str], target: str, info: dict, tunnel_edge: str | None):
    """Рисует цепочку маршрута. Если следующий роутер сам знает сеть — вешаем маршрут на линк к нему."""
    for x, y in zip(chain, chain[1:]):
        if y.startswith("gw:"):
            g.node(y, kind="gateway", label=y[3:])
            if x.startswith("n:"):
                g.edge(x, y, "lan")
        elif x.startswith("n:") and y.startswith("r:"):
            g.edge(x, y, "lan")
    last = chain[-1]
    if last == target:
        return
    if last.startswith("r:") and len(chain) > 1 and ctx.handles(last[2:], info["dst"]):
        e = g.edges.get(tunnel_edge) if tunnel_edge else g.edges.get(g.pairs.get(frozenset(chain[-2:]), ""))
        if e is not None:
            e["routes"].append(info)
            e["transit"] = True
        return
    g.network(info["dst"])
    e = g.edge(last, target, "route", active=False, protocols=[], via_vpn=None)
    e["routes"].append(info)
    if info["active"]:
        e["active"] = True
    if info["protocol"] not in e.setdefault("protocols", []):
        e["protocols"].append(info["protocol"])
    if info["vpn"] and not e.get("via_vpn"):
        e["via_vpn"] = info["vpn"]


def build(snaps: list[dict], tables: set[str] | None = None, protocols: set[str] | None = None,
          inactive: bool = True, default: bool = True, down_peers: bool = False) -> dict:
    ctx = Context(snaps)
    g = Graph()
    protocols = protocols or set(ALL_PROTOCOLS)

    # туннели, через которые идёт хоть один маршрут
    used = set()
    for s in ctx.ok.values():
        for r in s["routes"]:
            if r["protocol"] == "connected":
                continue
            for hop in r["hops"]:
                t = ctx.resolve_hop(s, r, hop)["tunnel"]
                if t:
                    used.add(t["uid"])
    hidden = [t for t in ctx.tunnels if not down_peers and t["family"] == "wireguard" and t["state"] == "down"
              and not t["pair"] and t["uid"] not in used]
    hidden_ids = {t["uid"] for t in hidden}

    for s in ctx.snaps.values():
        up = sum(t["state"] == "up" for t in s["tunnels"])
        g.node(f"r:{s['name']}", kind="router", router=s["name"], ok=s["ok"], error=s["error"],
               label=f"{s['identity']}\n{s['host']}", identity=s["identity"], host=s["host"],
               version=s["version"], board=s.get("board", ""), transport=s["transport"],
               routes=len(s["routes"]), tunnels=len(s["tunnels"]), tunnels_up=up, warnings=s["warnings"])

    # подключённые сети (кроме транзитных адресов VPN-интерфейсов)
    for s in ctx.ok.values():
        for a in s["addresses"]:
            if a["prefix"] >= 32 or a["vpn"]:
                continue
            n = g.network(a["cidr"], "lan")
            n["role"] = "lan" if n["role"] == "remote" else n["role"]
            n["attached"].append(f"{s['identity']}: {a['interface']} {a['ip']}")
            ifc = s["interfaces"].get(a["interface"], {})
            g.edge(f"r:{s['name']}", n["id"], "connected", label=a["interface"], ip=a["ip"],
                   up=ifc.get("running", True), router=s["name"], interface=a["interface"])

    # туннели
    by_uid = {t["uid"]: t for t in ctx.tunnels}
    for t in ctx.tunnels:
        if t["edge_id"] in g.edges or t["uid"] in hidden_ids:
            continue
        other = by_uid.get(t["pair"]) if t["pair"] else None
        if t["peer_node"].startswith("peer:"):
            g.node(t["peer_node"], kind="vpn-peer", vpn=t["family"],
                   label="\n".join(dict.fromkeys(x for x in (t["label"], t["remote_host"]) if x)))
        sides = [t] + ([other] if other else [])
        states = {x["state"] for x in sides}
        state = "up" if states == {"up"} else "down" if states == {"down"} else \
            "idle" if "down" not in states else "partial"
        kind = KIND_LABELS.get(t["family"], t["family"])
        ipsec = any(x["ipsec"] for x in sides)
        g.edge(f"r:{t['router']}", t["peer_node"], "tunnel", eid=t["edge_id"], index=False,
               vpn=t["family"], state=state, ipsec=ipsec,
               label=kind + (" + IPsec" if ipsec and t["family"] != "ipsec" else ""),
               sides=[{k: x[k] for k in ("router", "kind", "interface", "label", "state", "remote_host",
                                         "local_ips", "routed_nets", "details")} for x in sides])

    # маршруты
    for s in ctx.ok.values():
        for r in s["routes"]:
            if r["protocol"] == "connected":
                continue
            if tables is not None and r["table"] not in tables:
                continue
            if r["protocol"] not in protocols or (not r["active"] and not inactive):
                continue
            if r["dst"] == "0.0.0.0/0" and not default:
                continue
            # маршрут-"заглушка" под IPsec-политику: трафик всё равно заберёт политика
            pol = next((t for t in ctx.tunnels if t["router"] == s["name"] and t["kind"] == "ipsec"
                        and any(_subnet_of(r["dst"], n) for n in t["routed_nets"])), None)
            for hop in r["hops"] or [{}]:
                res = ctx.resolve_hop(s, r, hop)
                if pol and res["via"] != "vpn":
                    info = _route_info(s, r, hop, res)
                    info.update(tunnel=f"перехвачен {pol['label']}", vpn="ipsec")
                    if pol["edge_id"] in g.edges:
                        g.edges[pol["edge_id"]]["routes"].append(info)
                    continue
                chain = [f"r:{s['name']}"] + res["nodes"]
                _add_route(g, ctx, chain, dst_node(r["dst"]), _route_info(s, r, hop, res),
                           res["tunnel"]["edge_id"] if res["tunnel"] else None)

    # policy-based IPsec: сети за удалённой стороной
    if "ipsec" in protocols:
        for t in ctx.tunnels:
            if t["kind"] != "ipsec":
                continue
            for dst in t["routed_nets"]:
                info = {"router": t["router"], "dst": dst, "gateway": t["remote_host"] or "", "interface": "",
                        "protocol": "ipsec", "table": "ipsec-policy", "distance": 0,
                        "active": t["state"] == "up", "via": "vpn", "tunnel": t["label"], "vpn": "ipsec"}
                _add_route(g, ctx, [f"r:{t['router']}", t["peer_node"]], dst_node(dst), info, t["edge_id"])

    # роль "wan" — сеть со шлюзом маршрута по умолчанию
    for s in ctx.ok.values():
        for r in s["routes"]:
            if r["dst"] == "0.0.0.0/0" and r["table"] == "main":
                for h in r["hops"]:
                    a = find_connected(s, h["gateway"]) if h.get("gateway") else None
                    if a and f"n:{a['cidr']}" in g.nodes:
                        g.nodes[f"n:{a['cidr']}"]["role"] = "wan"

    for e in g.edges.values():
        e["label"] = e.get("label") or _edge_label(e)

    return {
        "nodes": list(g.nodes.values()),
        "edges": list(g.edges.values()),
        "tunnels": [_tunnel_row(t, ctx) for t in ctx.tunnels
                    if (not t["pair"] or t["uid"] < t["pair"]) and t["uid"] not in hidden_ids],
        "hidden_peers": len(hidden),
        "tables": sorted({r["table"] for s in ctx.ok.values() for r in s["routes"]} | {"main"}),
        "routers": [{"name": s["name"], "identity": s["identity"], "host": s["host"], "ok": s["ok"],
                     "error": s["error"], "version": s["version"], "transport": s["transport"],
                     "warnings": s["warnings"], "poll_ms": s.get("poll_ms")} for s in ctx.snaps.values()],
    }


def _edge_label(e: dict) -> str:
    if e["kind"] != "route":
        return ""
    parts = []
    for r in e["routes"]:
        p = r["protocol"]
        if r["table"] != "main":
            p += f" [{r['table']}]"
        if p not in parts:
            parts.append(p)
    return ", ".join(parts[:3]) + ("…" if len(parts) > 3 else "")


def _tunnel_row(t: dict, ctx: Context) -> dict:
    other = next((x for x in ctx.tunnels if x["uid"] == t["pair"]), None)
    peer = ctx.snaps[t["peer_router"]]["identity"] if t["peer_router"] else (t["remote_host"] or "?")
    states = {t["state"]} | ({other["state"]} if other else set())
    return {
        "edge_id": t["edge_id"], "vpn": t["family"], "kind_label": KIND_LABELS.get(t["family"], t["family"]),
        "a": ctx.snaps[t["router"]]["identity"], "a_iface": t["interface"] or t["label"],
        "b": peer, "b_iface": (other["interface"] or other["label"]) if other else None,
        "managed_both": bool(other), "ipsec": t["ipsec"] or bool(other and other["ipsec"]),
        "state": "up" if states == {"up"} else "down" if states == {"down"} else
        "idle" if "down" not in states else "partial",
        "details": t["details"], "routed_nets": t["routed_nets"],
    }


# ---------------------------------------------------------------- трассировка

def _lookup(snap: dict, ip: str, table: str) -> dict | None:
    def best(tbl):
        cands = [r for r in snap["routes"]
                 if r["active"] and r["table"] == tbl and r["protocol"] != "connected" and _in(ip, r["dst"])]
        return max(cands, key=lambda r: (r["prefix"], -r["distance"]), default=None)

    return best(table) or (best("main") if table != "main" else None)


def _pick_table(snap: dict, dst: str, src: str | None) -> tuple[str, dict | None]:
    for rule in snap["rules"]:
        if rule["interface"] or rule["mark"]:
            continue  # входящий интерфейс и routing-mark (mangle) по адресам не вычислить
        if rule["src"] and not (src and _in(src, rule["src"])):
            continue
        if rule["dst"] and not _in(dst, rule["dst"]):
            continue
        return rule["table"], rule
    return "main", None


def _addr_match(ip: str | None, spec: str | None, neg: bool = False) -> bool:
    """Условие адреса правила RouterOS: CIDR, адрес или диапазон a-b, с отрицанием '!'."""
    if not spec:
        return True
    if not ip:
        return False
    try:
        if "-" in spec:
            lo, hi = (ipaddress.ip_address(x.strip()) for x in spec.split("-", 1))
            hit = lo <= ipaddress.ip_address(ip) <= hi
        else:
            hit = _in(ip, spec)
    except ValueError:
        return False
    return hit != neg


def _ipsec_match(ctx: Context, router: str, src: str | None, dst: str) -> tuple[dict | None, dict | None, list]:
    """Первая tunnel-политика по паре src+dst; плюс политики, подходящие только по dst."""
    near = []
    for t in ctx.tunnels:
        if t["router"] != router or t["kind"] != "ipsec":
            continue
        for p in t.get("policies", []):
            if not p["dst"] or not _in(dst, p["dst"]):
                continue
            if (src and _in(src, p["src"])) or p["src"] == "0.0.0.0/0":
                return t, p, near
            near.append((t, p))
    return None, None, near


def _iface_addr(snap: dict, iface: str | None, gw: str | None) -> str | None:
    """Адрес роутера на egress-интерфейсе (так выбирает masquerade и локальный источник)."""
    if not iface:
        return None
    if gw:
        a = find_connected(snap, gw, iface)
        if a and a["interface"] == iface:
            return a["ip"]
    return next((a["ip"] for a in snap["addresses"] if a["interface"] == iface), None)


def _nat_cond(rule: dict) -> str:
    parts = []
    for key, label in (("src", "src"), ("dst", "dst"), ("out_interface", "out"), ("out_list", "out-list")):
        if rule[key]:
            parts.append(f"{label} {'!' if rule[key + '_neg'] else ''}{rule[key]}")
    if rule["ipsec_policy"]:
        parts.append(f"ipsec-policy={rule['ipsec_policy']}")
    return ", ".join(parts) or "любой трафик"


def _srcnat(ctx: Context, snap: dict, src: str | None, dst: str, egress: str | None,
            gw: str | None) -> tuple[str | None, dict | None, list]:
    """Первое подходящее правило chain=srcnat → (новый src, правило, неучтённые правила)."""
    skipped = []
    for rule in snap.get("nat", []):
        if not (_addr_match(src, rule["src"], rule["src_neg"]) and _addr_match(dst, rule["dst"], rule["dst_neg"])):
            continue
        if rule["out_interface"] and (not egress or (egress == rule["out_interface"]) == rule["out_interface_neg"]):
            continue
        if rule["out_list"]:
            members = snap.get("iface_lists", {}).get(rule["out_list"], [])
            inside = rule["out_list"] == "all" or egress in members
            if not egress or inside == rule["out_list_neg"]:
                continue
        pol = (rule["ipsec_policy"] or "").replace(" ", "")
        if pol in ("out,none", "out,ipsec"):
            # условие проверяет, попадёт ли пакет в IPsec-политику с текущим src
            if (_ipsec_match(ctx, snap["name"], src, dst)[0] is not None) != (pol == "out,ipsec"):
                continue
        elif pol:
            skipped.append(rule)
            continue
        if rule["extra"]:
            skipped.append(rule)
            continue
        act = rule["action"]
        if act in ("passthrough", "log", "add-src-to-address-list", "add-dst-to-address-list"):
            continue
        if act == "masquerade":
            return _iface_addr(snap, egress, gw), rule, skipped
        if act in ("src-nat", "same") and rule["to_addresses"]:
            return rule["to_addresses"].split("-")[0].strip(), rule, skipped
        if act == "netmap" and rule["to_addresses"] and src:
            try:
                to = ipaddress.ip_network(rule["to_addresses"].split("-")[0].strip(), strict=False)
                host = int(ipaddress.ip_address(src)) & int(to.hostmask)
                return str(ipaddress.ip_address(int(to.network_address) | host)), rule, skipped
            except ValueError:
                pass
        return src, rule, skipped  # accept и прочие — без трансляции, дальше правила не смотрятся
    return src, None, skipped


def _nat_steps(name: str, src: str | None, new: str | None, rule: dict | None, skipped: list,
               egress: str | None) -> list[dict]:
    steps = []
    for r in skipped[:3]:
        extra = ", ".join(f"{k}={v}" for k, v in r["extra"].items()) or f"ipsec-policy={r['ipsec_policy']}"
        steps.append({"router": name, "action": "info",
                      "text": f"srcnat: правило {r['id']} {r['action']} ({_nat_cond(r)}; {extra}) не учтено — "
                              f"зависит от условий, которые по адресам не проверить"})
    if rule is None:
        return steps
    where = f", egress {egress}" if egress else ""
    comment = f", «{rule['comment']}»" if rule["comment"] else ""
    if rule["action"] == "masquerade" and new is None:
        text = f"srcnat: masquerade ({_nat_cond(rule)}{where}) — адрес роутера на {egress or '?'} неизвестен"
    elif new != src:
        text = f"srcnat: {src or '?'} → {new} ({rule['action']} {rule['id']}: {_nat_cond(rule)}{where}{comment})"
    elif rule["action"] == "masquerade":
        text = f"srcnat: masquerade {rule['id']} ({_nat_cond(rule)}) — src {src} уже адрес роутера на {egress}"
    else:
        text = f"srcnat: правило {rule['action']} {rule['id']} ({_nat_cond(rule)}{comment}) — src {src} без трансляции"
    steps.append({"router": name, "action": "nat" if new != src else "info", "text": text})
    return steps


def trace(snaps: list[dict], router: str, dst: str, src: str | None = None, table: str | None = None) -> dict:
    ctx = Context(snaps)
    if router not in ctx.ok:
        return {"ok": False, "steps": [{"router": router, "action": "error", "text": "роутер недоступен"}],
                "path": [], "tunnel_edges": []}
    steps, path, tedges = [], [f"r:{router}"], []
    cur, visited, ok = router, set(), False
    for _ in range(16):
        s = ctx.ok.get(cur)
        if s is None:
            steps.append({"router": cur, "action": "error", "text": "нет данных с роутера"})
            break
        name = s["identity"]
        if cur in visited:
            steps.append({"router": name, "action": "loop", "text": "петля маршрутизации"})
            break
        visited.add(cur)

        if dst in s["ips"]:
            steps.append({"router": name, "action": "local", "text": f"{dst} — адрес этого роутера"})
            ok = True
            break

        a = find_connected(s, dst)
        if a:
            new, rule, skipped = _srcnat(ctx, s, src, dst, a["interface"], None)
            t = ctx.choose_tunnel(cur, a["interface"], dst, None) if a["vpn"] else None
            if t:
                path.append(t["peer_node"])
                tedges.append(t["edge_id"])
                steps.append({"router": name, "action": "connected",
                              "text": f"подключена через туннель {t['label']} ({a['interface']})"})
            else:
                path.append(f"n:{a['cidr']}")
                owner = ctx.ip_owner.get(dst)
                if owner and owner != cur:
                    path.append(f"r:{owner}")
                steps.append({"router": name, "action": "connected",
                              "text": f"сеть {a['cidr']} подключена к {a['interface']}"})
            steps.extend(_nat_steps(name, src, new, rule, skipped, a["interface"]))
            ok = True
            break

        # RouterOS: маршрут (egress) → srcnat → IPsec-политика по уже транслированному src
        tbl, rule = (table, None) if table else _pick_table(s, dst, src)
        table = None  # явно заданная таблица — только для первого роутера
        r = _lookup(s, dst, tbl)
        if r is None:
            steps.append({"router": name, "action": "no-route", "text": f"нет маршрута в таблице {tbl}"})
            pol, match, _ = _ipsec_match(ctx, cur, src, dst)
            if pol:
                steps.append({"router": name, "action": "info",
                              "text": f"есть IPsec-политика {match['src']} → {match['dst']} ({pol['label']}), "
                                      f"но без маршрута пакет отбрасывается раньше проверки политики"})
            break
        if r["protocol"] == "blackhole":
            steps.append({"router": name, "action": "blackhole", "text": f"blackhole {r['dst']}"})
            path.append(dst_node(r["dst"]))
            break
        hop = r["hops"][0] if r["hops"] else {}
        gw, egress = hop.get("gateway"), hop.get("interface")
        if not egress and gw:
            ga = find_connected(s, gw)
            egress = ga["interface"] if ga else None
        if src is None and cur == router:
            src = _iface_addr(s, egress, gw)
            if src:
                steps.append({"router": name, "action": "info",
                              "text": f"источник не задан — берём адрес роутера на {egress}: {src}"})
        new, nat_rule, skipped = _srcnat(ctx, s, src, dst, egress, gw)
        steps.extend(_nat_steps(name, src, new, nat_rule, skipped, egress))
        src = new

        pol, match, near = _ipsec_match(ctx, cur, src, dst)
        if pol:
            path.append(pol["peer_node"])
            tedges.append(pol["edge_id"])
            steps.append({"router": name, "action": "ipsec",
                          "text": f"IPsec-политика {match['src']} → {match['dst']} через {pol['remote_host']}",
                          "state": pol["state"]})
            if pol["peer_router"]:
                cur = pol["peer_router"]
                continue
            path.append(dst_node(match["dst"]))
            ok = True
            break
        for t, p in near[:3]:
            why = f"источник {src} не из {p['src']}" if src else f"источник не задан — нужен из {p['src']}"
            steps.append({"router": name, "action": "info",
                          "text": f"IPsec-политика {p['src']} → {p['dst']} ({t['label']}) не сработала: {why}"})

        res = ctx.resolve_hop(s, r, hop)
        via = gw or hop.get("interface") or "?"
        text = f"{r['dst']} via {via} ({r['protocol']}, dist {r['distance']}"
        text += f", таблица {tbl}" + (f" по правилу src {rule['src']}" if rule and rule["src"] else "") + ")"
        if res["tunnel"]:
            text += f" → туннель {KIND_LABELS.get(res['tunnel']['family'])} «{res['tunnel']['label']}»"
            tedges.append(res["tunnel"]["edge_id"])
        if len(r["hops"]) > 1:
            text += f"; ECMP: {len(r['hops'])} шлюза"
        steps.append({"router": name, "action": "route", "text": text,
                      "state": res["tunnel"]["state"] if res["tunnel"] else None})
        path.extend(res["nodes"])
        if res["next_router"]:
            cur = res["next_router"]
            continue
        path.append(dst_node(r["dst"]))
        ok = True
        break
    if ok and any(st.get("state") == "down" for st in steps):
        ok = False
        steps.append({"router": steps[-1]["router"], "action": "tunnel-down",
                      "text": "маршрут есть, но туннель на пути не поднят — трафик не пройдёт"})
    # убираем повторы подряд
    clean = [p for i, p in enumerate(path) if i == 0 or p != path[i - 1]]
    return {"ok": ok, "steps": steps, "path": clean, "tunnel_edges": tedges, "src": src}
