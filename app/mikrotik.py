"""Сбор данных с MikroTik RouterOS и нормализация в единый "снимок" (snapshot).

Поддерживаются два транспорта:
  * rest     — REST API RouterOS v7 (https://host/rest/...), также "http" без TLS;
  * api      — классический API (8728), "api-ssl" — по TLS (8729). Работает и на RouterOS v6.

Парсер понимает форматы и v6 (gateway-status), и v7 (immediate-gw, routing-table).
"""
from __future__ import annotations

import ipaddress
import logging
import re
import ssl
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

# ключ снимка -> путь меню RouterOS
PATHS = {
    "identity": "system/identity",
    "resource": "system/resource",
    "interfaces": "interface",
    "addresses": "ip/address",
    "routes": "ip/route",
    "wg": "interface/wireguard",
    "wg_peers": "interface/wireguard/peers",
    "ipsec_peers": "ip/ipsec/peer",
    "ipsec_active": "ip/ipsec/active-peers",
    "ipsec_policies": "ip/ipsec/policy",
    "ovpn_client": "interface/ovpn-client",
    "l2tp_client": "interface/l2tp-client",
    "sstp_client": "interface/sstp-client",
    "pptp_client": "interface/pptp-client",
    "gre": "interface/gre",
    "ipip": "interface/ipip",
    "eoip": "interface/eoip",
    "ppp_active": "ppp/active",
    "rules7": "routing/rule",
    "rules6": "ip/route/rule",
    "nat": "ip/firewall/nat",
    "iface_lists": "interface/list/member",
}
# без них снимок бессмыслен — ошибка = роутер недоступен
REQUIRED = ("identity", "interfaces", "addresses", "routes")

# /interface type -> вид VPN
VPN_IFACE_TYPES = {
    "wg": "wireguard",
    "ovpn-out": "ovpn-client", "ovpn-in": "ovpn-server",
    "l2tp-out": "l2tp-client", "l2tp-in": "l2tp-server",
    "sstp-out": "sstp-client", "sstp-in": "sstp-server",
    "pptp-out": "pptp-client", "pptp-in": "pptp-server",
    "gre-tunnel": "gre", "gre6-tunnel": "gre",
    "ipip-tunnel": "ipip", "ipip6-tunnel": "ipip",
    "eoip-tunnel": "eoip", "eoipv6-tunnel": "eoip",
    "vxlan": "vxlan", "zerotier": "zerotier",
}

WG_UP_SECONDS = 180  # ключи сессии WireGuard живут 180с без рукопожатия


@dataclass
class RouterConfig:
    name: str
    host: str
    transport: str = "rest"  # rest | http | api | api-ssl | opnsense
    port: int | None = None
    username: str = "admin"
    password: str = ""
    verify_tls: bool = False
    timeout: float = 10.0
    public_ips: list[str] = field(default_factory=list)
    max_routes: int = 2000
    demo: bool = False


# ---------------------------------------------------------------- транспорт

class RestTransport:
    def __init__(self, cfg: RouterConfig):
        import httpx

        scheme = "http" if cfg.transport == "http" else "https"
        port = cfg.port or (80 if scheme == "http" else 443)
        self.client = httpx.Client(
            base_url=f"{scheme}://{cfg.host}:{port}/rest",
            auth=(cfg.username, cfg.password),
            verify=cfg.verify_tls,
            timeout=cfg.timeout,
            trust_env=False,  # системный HTTP(S)_PROXY до роутеров в LAN обычно не достаёт
        )

    def get(self, path: str) -> list[dict]:
        r = self.client.get("/" + path)
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, list) else [data]

    def close(self):
        self.client.close()


class ApiTransport:
    def __init__(self, cfg: RouterConfig):
        import librouteros

        kwargs = {"port": cfg.port or (8729 if cfg.transport == "api-ssl" else 8728), "timeout": cfg.timeout}
        if cfg.transport == "api-ssl":
            ctx = ssl.create_default_context()
            if not cfg.verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            kwargs["ssl_wrapper"] = lambda sock: ctx.wrap_socket(sock, server_hostname=cfg.host)
        self.api = librouteros.connect(host=cfg.host, username=cfg.username, password=cfg.password, **kwargs)

    def get(self, path: str) -> list[dict]:
        rows = self.api.path(*path.split("/"))
        return [{k: _str(v) for k, v in row.items()} for row in rows]

    def close(self):
        self.api.close()


def _str(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def collect(cfg: RouterConfig) -> dict:
    """Опрашивает роутер и возвращает сырые данные {ключ: [строки]}."""
    transport = RestTransport(cfg) if cfg.transport in ("rest", "http", "https") else ApiTransport(cfg)
    raw: dict = {"_errors": {}, "_transport": cfg.transport}
    try:
        for key, path in PATHS.items():
            try:
                raw[key] = transport.get(path)
            except Exception as e:  # noqa: BLE001 — меню может отсутствовать (нет пакета, v6/v7)
                if key in REQUIRED:
                    raise
                raw["_errors"][key] = str(e)[:200]
                raw[key] = []
    finally:
        transport.close()
    return raw


# ---------------------------------------------------------------- помощники

def b(v) -> bool:
    return str(v).lower() in ("true", "yes")


def ip_or_none(s) -> str | None:
    if not s:
        return None
    s = str(s).strip().split("/")[0]
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        # "1.2.3.4:1194" (caller-id OpenVPN)
        if s.count(":") == 1:
            return ip_or_none(s.split(":")[0])
        return None


def norm_net(s: str) -> str | None:
    try:
        return str(ipaddress.ip_network(s.strip(), strict=False))
    except ValueError:
        return None


_DUR = re.compile(r"(\d+)(ms|w|d|h|m|s)")
_UNITS = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1, "ms": 0.001}


def parse_duration(s) -> float | None:
    """'1w2d3h4m5s', '45s', '1d00:01:05', '00:01:05' -> секунды."""
    if not s:
        return None
    s = str(s).strip()
    total = 0.0
    m = re.search(r"(\d+):(\d+):(\d+)$", s)
    if m:
        total += int(m[1]) * 3600 + int(m[2]) * 60 + int(m[3])
        s = s[: m.start()]
    parts = _DUR.findall(s)
    if not parts and not m:
        return None
    for num, unit in parts:
        total += int(num) * _UNITS[unit]
    return total


def find_connected(snap: dict, ip: str, iface: str | None = None) -> dict | None:
    """Адрес роутера, через сеть которого достижим ip (самый длинный префикс)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    best = None
    for a in snap["addresses"]:
        if a["peer"] == ip:
            hit = 33
        elif a["prefix"] < 32 and addr in ipaddress.ip_network(a["cidr"]):
            hit = a["prefix"]
        else:
            continue
        if iface and a["interface"] == iface:
            hit += 100
        if best is None or hit > best[0]:
            best = (hit, a)
    return best[1] if best else None


# ---------------------------------------------------------------- парсинг

def error_snapshot(cfg: RouterConfig, err: Exception | str) -> dict:
    return {
        "name": cfg.name, "host": cfg.host, "transport": cfg.transport, "ok": False,
        "error": str(err)[:300] or err.__class__.__name__, "identity": cfg.name, "version": "",
        "board": "", "interfaces": {}, "addresses": [], "routes": [], "tunnels": [], "rules": [],
        "tables": [], "ips": [], "warnings": [], "nat": [], "iface_lists": {},
    }


def parse(cfg: RouterConfig, raw: dict) -> dict:
    name = cfg.name
    ident = (raw.get("identity") or [{}])[0].get("name", name)
    res = (raw.get("resource") or [{}])[0]

    interfaces = {}
    for r in raw.get("interfaces", []):
        t = r.get("type", "")
        interfaces[r.get("name", "")] = {
            "name": r.get("name", ""), "type": t, "running": b(r.get("running")),
            "disabled": b(r.get("disabled")), "comment": r.get("comment", ""),
            "vpn": VPN_IFACE_TYPES.get(t),
        }

    addresses = []
    for r in raw.get("addresses", []):
        if b(r.get("disabled")):
            continue
        try:
            ifc = ipaddress.ip_interface(r.get("address", ""))
        except ValueError:
            continue
        if ifc.version != 4:
            continue
        ip = str(ifc.ip)
        prefix = ifc.network.prefixlen
        peer = None
        net = r.get("network")
        if prefix == 32 and net and net != ip:
            peer = net  # point-to-point (PPP): network = адрес удалённой стороны
        iface = r.get("interface", "")
        if b(r.get("invalid")) or (interfaces.get(iface) or {}).get("disabled"):
            continue  # адрес на выключенном интерфейсе не работает
        addresses.append({
            "ip": ip, "prefix": prefix, "cidr": str(ifc.network), "peer": peer, "interface": iface,
            "dynamic": b(r.get("dynamic")), "vpn": (interfaces.get(iface) or {}).get("vpn"),
        })

    snap = {
        "name": name, "host": cfg.host, "transport": cfg.transport, "ok": True, "error": None,
        "identity": ident, "version": res.get("version", ""), "board": res.get("board-name", ""),
        "uptime": res.get("uptime", ""), "interfaces": interfaces, "addresses": addresses,
        "warnings": [f"{k}: {v}" for k, v in raw.get("_errors", {}).items()
                     if not any(x in v.lower() for x in ("no such command", "'400", "'404"))],
    }
    snap["routes"] = _parse_routes(raw.get("routes", []), snap, cfg.max_routes)
    snap["tunnels"] = _parse_tunnels(raw, snap)
    snap["rules"] = _parse_rules(raw)
    snap["nat"] = _parse_nat(raw)
    snap["iface_lists"] = _parse_iface_lists(raw)
    snap["tables"] = sorted({r["table"] for r in snap["routes"]} | {"main"})
    ips = {a["ip"] for a in addresses} | set(cfg.public_ips)
    if ip_or_none(cfg.host):
        ips.add(ip_or_none(cfg.host))
    snap["ips"] = sorted(ips)
    return snap


_GW_STATUS = re.compile(r"(\S+)\s+reachable\s+via\s+(\S+)")


def _protocol(r: dict) -> str:
    if b(r.get("connect")):
        return "connected"
    if b(r.get("blackhole")) or r.get("type") in ("blackhole", "unreachable", "prohibit"):
        return "blackhole"
    for p in ("ospf", "bgp", "rip"):
        if b(r.get(p)):
            return p
    if b(r.get("static")):
        return "static"
    if b(r.get("dynamic")):
        return "dynamic"
    return "static"


def _parse_routes(rows: list[dict], snap: dict, limit: int) -> list[dict]:
    ifaces = snap["interfaces"]
    routes = []
    for r in rows:
        dst = norm_net(r.get("dst-address", ""))
        if not dst or ":" in dst or b(r.get("disabled")):
            continue
        proto = _protocol(r)
        # egress-интерфейс по шлюзу: v7 immediate-gw "ip%iface", v6 gateway-status "ip reachable via iface"
        egress = {}
        for part in r.get("immediate-gw", "").split(","):
            if part:
                gw, _, ifc = part.partition("%")
                egress[gw] = ifc or gw
        for m in _GW_STATUS.finditer(r.get("gateway-status", "")):
            egress.setdefault(m[1], m[2])
        hops = []
        for gw in [g.strip() for g in r.get("gateway", "").split(",") if g.strip()]:
            gw_ip, _, gw_if = gw.partition("%")
            if ip_or_none(gw_ip):
                iface = gw_if or egress.get(gw_ip)
                if not iface:
                    a = find_connected(snap, gw_ip)
                    iface = a["interface"] if a else None
                hops.append({"gateway": gw_ip, "interface": iface})
            else:  # шлюз — имя интерфейса
                hops.append({"gateway": None, "interface": gw})
        if not hops and proto != "blackhole":
            hops.append({"gateway": None, "interface": r.get("vrf-interface") or None})
        for h in hops:
            if h["interface"] and h["interface"] in ifaces:
                h["vpn"] = ifaces[h["interface"]]["vpn"]
        try:
            distance = int(r.get("distance", 0) or 0)
        except ValueError:
            distance = 0
        routes.append({
            "id": r.get(".id", ""), "dst": dst, "prefix": int(dst.split("/")[1]),
            "gateway": r.get("gateway", ""), "hops": hops, "protocol": proto,
            "active": b(r.get("active")), "distance": distance,
            "table": r.get("routing-table") or r.get("routing-mark") or "main",
            "comment": r.get("comment", ""),
        })
    if len(routes) > limit:
        snap["warnings"].append(f"маршрутов {len(routes)}, показаны первые {limit} (max_routes)")
        routes.sort(key=lambda x: (not x["active"], x["protocol"] == "bgp"))
        routes = routes[:limit]
    return routes


def _tunnel(snap: dict, tid: str, kind: str, iface: str | None, label: str, state: str, **kw) -> dict:
    addrs = [a for a in snap["addresses"] if iface and a["interface"] == iface]
    t = {
        "uid": f"{snap['name']}/{tid}", "id": tid, "router": snap["name"], "kind": kind,
        "family": kind.replace("-client", "").replace("-server", ""), "interface": iface,
        "label": label, "state": state, "remote_public": None, "remote_host": None,
        "local_public": None, "local_ips": [a["ip"] for a in addrs],
        "local_nets": [a["cidr"] for a in addrs if a["prefix"] < 32],
        "remote_nets": [f"{a['peer']}/32" for a in addrs if a["peer"]],
        "routed_nets": [], "ipsec": False, "details": {},
    }
    t.update(kw)
    return t


def _iface_up(snap: dict, name: str) -> bool:
    i = snap["interfaces"].get(name)
    return bool(i and i["running"] and not i["disabled"])


def _parse_tunnels(raw: dict, snap: dict) -> list[dict]:
    tunnels = []

    # WireGuard: каждый peer — отдельный туннель
    for p in raw.get("wg_peers", []):
        if b(p.get("disabled")):
            continue
        iface = p.get("interface", "")
        hs = parse_duration(p.get("last-handshake"))
        if not _iface_up(snap, iface) or hs is None:
            state = "down"
        else:
            state = "up" if hs <= WG_UP_SECONDS else "idle"
        endpoint = p.get("current-endpoint-address") or p.get("endpoint-address") or ""
        allowed = [n for n in (norm_net(x) for x in p.get("allowed-address", "").split(",") if x.strip()) if n]
        t = _tunnel(
            snap, f"wg:{iface}:{p.get('.id', len(tunnels))}", "wireguard", iface,
            p.get("comment") or p.get("name") or f"{iface} → {endpoint or 'peer'}", state,
            remote_public=ip_or_none(endpoint), remote_host=endpoint or None, routed_nets=allowed,
            details={
                "рукопожатие": p.get("last-handshake") or "никогда",
                "endpoint": f"{endpoint}:{p.get('current-endpoint-port') or p.get('endpoint-port', '')}" if endpoint else "—",
                "peer": p.get("name", ""), "allowed-address": p.get("allowed-address", ""),
                "rx": p.get("rx", ""), "tx": p.get("tx", ""),
            },
        )
        t["remote_nets"] += [n for n in allowed if int(n.split("/")[1]) >= 16]
        tunnels.append(t)

    # PPP-клиенты
    for key, kind in (("ovpn_client", "ovpn-client"), ("l2tp_client", "l2tp-client"),
                      ("sstp_client", "sstp-client"), ("pptp_client", "pptp-client")):
        for r in raw.get(key, []):
            if b(r.get("disabled")):
                continue
            name = r.get("name", "")
            up = b(r.get("running")) or _iface_up(snap, name)
            ct = r.get("connect-to", "")
            tunnels.append(_tunnel(
                snap, f"{kind}:{name}", kind, name, name, "up" if up else "down",
                remote_public=ip_or_none(ct), remote_host=ct or None, ipsec=b(r.get("use-ipsec")),
                details={"connect-to": ct, "user": r.get("user", "")},
            ))

    # PPP-сервер: динамические интерфейсы <l2tp-user> + /ppp/active
    ppp = raw.get("ppp_active", [])
    for ifc in snap["interfaces"].values():
        if not ifc["type"].endswith("-in") or not ifc["vpn"]:
            continue
        svc = ifc["type"][:-3]
        m = re.fullmatch(r"<(\w+)-(.+)>", ifc["name"])
        user = m[2] if m else ifc["name"]
        act = next((a for a in ppp if a.get("name") == user and a.get("service", svc) == svc), None) \
            or next((a for a in ppp if a.get("name") and a["name"] in ifc["name"]), {})
        caller = act.get("caller-id", "")
        tunnels.append(_tunnel(
            snap, f"{ifc['vpn']}:{ifc['name']}", ifc["vpn"], ifc["name"], f"{svc} ← {user}",
            "up" if ifc["running"] else "down",
            remote_public=ip_or_none(caller), remote_host=caller or None,
            details={"user": user, "caller-id": caller, "uptime": act.get("uptime", ""),
                     "адрес": act.get("address", "")},
        ))

    # GRE / IPIP / EoIP
    for key in ("gre", "ipip", "eoip"):
        for r in raw.get(key, []):
            if b(r.get("disabled")):
                continue
            name = r.get("name", "")
            up = b(r.get("running")) or _iface_up(snap, name)
            remote = r.get("remote-address", "")
            tunnels.append(_tunnel(
                snap, f"{key}:{name}", key, name, name, "up" if up else "down",
                remote_public=ip_or_none(remote), remote_host=remote or None,
                local_public=ip_or_none(r.get("local-address")), ipsec=bool(r.get("ipsec-secret")),
                details={"remote": remote, "local": r.get("local-address", ""),
                         "tunnel-id": r.get("tunnel-id", ""), "keepalive": r.get("keepalive", "")},
            ))

    # IPsec site-to-site (policy-based): группируем tunnel-политики по peer
    peers = {p.get("name", ""): p for p in raw.get("ipsec_peers", []) if not b(p.get("disabled"))}
    established = {ip_or_none(a.get("remote-address")) for a in raw.get("ipsec_active", [])
                   if a.get("state", "established") == "established"}
    groups: dict[str, dict] = {}
    for pol in raw.get("ipsec_policies", []):
        if b(pol.get("disabled")) or b(pol.get("template")) or b(pol.get("invalid")):
            continue
        if not b(pol.get("tunnel")) or pol.get("action", "encrypt") != "encrypt":
            continue  # transport-политики защищают другой туннель (L2TP/GRE over IPsec)
        peer_name = pol.get("peer", "")
        remote = ip_or_none(pol.get("sa-dst-address")) or ip_or_none(peers.get(peer_name, {}).get("address"))
        key = peer_name or remote or pol.get(".id", "")
        g = groups.setdefault(key, {"peer": peer_name, "remote": remote,
                                    "local": ip_or_none(pol.get("sa-src-address")), "pols": []})
        g["pols"].append(pol)
    for key, g in groups.items():
        up = any(p.get("ph2-state") == "established" for p in g["pols"]) or g["remote"] in established
        dsts = list(dict.fromkeys(n for n in (norm_net(p.get("dst-address", "")) for p in g["pols"]) if n))
        tunnels.append(_tunnel(
            snap, f"ipsec:{key}", "ipsec", None, f"IPsec {g['peer'] or g['remote']}", "up" if up else "down",
            remote_public=g["remote"], remote_host=g["remote"], local_public=g["local"], routed_nets=dsts,
            policies=[{"src": norm_net(p.get("src-address", "")) or "0.0.0.0/0",
                       "dst": norm_net(p.get("dst-address", ""))} for p in g["pols"]],
            details={"peer": g["peer"], "политики": "; ".join(
                f"{p.get('src-address')} → {p.get('dst-address')} ({p.get('ph2-state', '?')})" for p in g["pols"])},
        ))

    # туннели поверх IPsec (L2TP use-ipsec, GRE ipsec-secret, ручные transport-политики)
    ipsec_remotes = established | {ip_or_none(p.get("address")) for p in peers.values()}
    for t in tunnels:
        if t["kind"] != "ipsec" and t["remote_public"] in ipsec_remotes:
            t["ipsec"] = True
    return tunnels


def _parse_rules(raw: dict) -> list[dict]:
    rules = []
    for r in raw.get("rules7", []) + raw.get("rules6", []):
        if b(r.get("disabled")):
            continue
        rules.append({
            "src": norm_net(r["src-address"]) if r.get("src-address") else None,
            "dst": norm_net(r["dst-address"]) if r.get("dst-address") else None,
            "interface": r.get("interface") or None, "mark": r.get("routing-mark") or None,
            "action": r.get("action", "lookup"), "table": r.get("table", "main"),
            "comment": r.get("comment", ""),
        })
    return rules


# поля правила NAT, которые не являются условиями
_NAT_META = {".id", ".nextid", ".about", "chain", "action", "to-addresses", "to-ports", "log", "log-prefix",
             "comment", "disabled", "invalid", "dynamic", "bytes", "packets", "place-before"}
# условия, которые трассировка умеет вычислять по адресам и egress-интерфейсу
_NAT_KNOWN = {"src-address", "dst-address", "out-interface", "out-interface-list", "ipsec-policy"}


def _neg(v: str | None) -> tuple[str | None, bool]:
    if not v:
        return None, False
    v = str(v).strip()
    return (v[1:], True) if v.startswith("!") else (v, False)


def _parse_nat(raw: dict) -> list[dict]:
    """Правила chain=srcnat в порядке RouterOS (первое подходящее срабатывает)."""
    rules = []
    for r in raw.get("nat", []):
        if r.get("chain") != "srcnat" or b(r.get("disabled")) or b(r.get("invalid")):
            continue
        rule = {"id": r.get(".id", ""), "action": r.get("action", "accept"),
                "to_addresses": r.get("to-addresses") or None, "comment": r.get("comment", "")}
        for key, f in (("src", "src-address"), ("dst", "dst-address"), ("out_interface", "out-interface"),
                       ("out_list", "out-interface-list")):
            rule[key], rule[key + "_neg"] = _neg(r.get(f))
        rule["ipsec_policy"] = r.get("ipsec-policy") or None
        # прочие условия (protocol, порты, address-list, mark…) по адресам не проверить;
        # priority=0 — значение по умолчанию у обычного трафика
        rule["extra"] = {k: v for k, v in r.items()
                         if k not in _NAT_META and k not in _NAT_KNOWN and not (k == "priority" and v == "0")}
        if rule["action"] in ("jump", "return"):
            rule["extra"].setdefault("action", rule["action"])  # пользовательские цепочки не разбираем
        rules.append(rule)
    return rules


def _parse_iface_lists(raw: dict) -> dict[str, list[str]]:
    lists: dict[str, list[str]] = {}
    for r in raw.get("iface_lists", []):
        if b(r.get("disabled")):
            continue
        lists.setdefault(r.get("list", ""), []).append(r.get("interface", ""))
    return lists
