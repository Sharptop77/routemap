"""Драйвер OPNsense: REST API (https://host/api/..., Basic-auth key:secret) → тот же снимок, что у MikroTik.

Проверено на живом OPNsense: таблица маршрутов (netstat), интерфейсы (overview/export), шлюзы,
source NAT. Разделы WireGuard / IPsec / OpenVPN разбираются по формату API OPNsense 24.x–25.x;
недоступный раздел (нет прав, выключен) не ломает опрос, а попадает в предупреждения.
"""
from __future__ import annotations

import ipaddress
import re
import time

from .mikrotik import RouterConfig, _tunnel, b, ip_or_none, norm_net

# ключ -> путь API (snake_case: camelCase-варианты на новых версиях отдают 403)
ENDPOINTS = {
    "routes": "diagnostics/interface/get_routes",
    "interfaces": "interfaces/overview/export",
    "gateways": "routes/gateway/status",
    "sysinfo": "diagnostics/system/system_information",
    "wg_show": "wireguard/service/show",
    "wg_servers": "wireguard/server/search_server",
    "ipsec_p1": "ipsec/sessions/search_phase1",
    "ipsec_conn": "ipsec/connections/search_connection",
    "ipsec_child": "ipsec/connections/search_child",
    "ovpn_sessions": "openvpn/service/search_sessions",
    "ovpn_instances": "openvpn/instances/search",
    "gre": "interfaces/gre_settings/search_item",
    "gif": "interfaces/gif_settings/search_item",
    "nat": "firewall/source_nat/search_rule",
}
REQUIRED = ("routes", "interfaces")

# префикс устройства FreeBSD -> вид VPN
DEVICE_VPN = (("wg", "wireguard"), ("ovpnc", "ovpn-client"), ("ovpns", "ovpn-server"), ("ipsec", "ipsec"),
              ("gre", "gre"), ("gif", "ipip"), ("vxlan", "vxlan"), ("tun_wg", "wireguard"))


def _device_vpn(dev: str) -> str | None:
    for prefix, kind in DEVICE_VPN:
        if re.fullmatch(rf"{prefix}\d+", dev or ""):
            return kind
    return None


def collect(cfg: RouterConfig) -> dict:
    import httpx

    port = cfg.port or 443
    raw: dict = {"_errors": {}, "_transport": "opnsense"}
    # trust_env=False: роутеры обычно в LAN, системный HTTP(S)_PROXY до них не достаёт
    with httpx.Client(base_url=f"https://{cfg.host}:{port}/api", auth=(cfg.username, cfg.password),
                      verify=cfg.verify_tls, timeout=cfg.timeout, trust_env=False) as c:
        for key, path in ENDPOINTS.items():
            try:
                r = c.get("/" + path)
                if r.status_code in (401, 403, 404) and key not in REQUIRED:
                    raw["_errors"][key] = f"HTTP {r.status_code}"
                    raw[key] = None
                    continue
                r.raise_for_status()
                raw[key] = r.json()
            except Exception as e:  # noqa: BLE001
                if key in REQUIRED:
                    raise
                raw["_errors"][key] = str(e)[:200]
                raw[key] = None
    return raw


def _rows(data) -> list[dict]:
    """search_* отдают {"rows": [...]}, export — список, gateway/status — {"items": [...]}."""
    if data is None:
        return []
    if isinstance(data, list):
        return data
    for k in ("rows", "items"):
        if isinstance(data.get(k), list):
            return data[k]
    return []


# права, которых не хватает ключу: ключ снимка -> страница в System → Access → Users → Privileges
PRIVILEGE_HINTS = {
    "sysinfo": "Dashboard (all) — имя хоста и версия",
    "wg_show": "VPN: WireGuard", "wg_servers": "VPN: WireGuard",
    "ipsec_p1": "Status: IPsec (или VPN: IPsec: Status)",
    "ipsec_conn": "VPN: IPsec: Connections", "ipsec_child": "VPN: IPsec: Connections",
    "ovpn_sessions": "Status: OpenVPN", "ovpn_instances": "VPN: OpenVPN: Instances",
    "gre": "Interfaces: Other Types: GRE", "gif": "Interfaces: Other Types: GIF",
    "nat": "Firewall: Source NAT",
}


def parse(cfg: RouterConfig, raw: dict) -> dict:
    sysinfo = raw.get("sysinfo") or {}
    versions = sysinfo.get("versions") or []
    snap = {
        "name": cfg.name, "host": cfg.host, "transport": "opnsense", "ok": True, "error": None,
        "identity": sysinfo.get("name") or cfg.name, "version": versions[0] if versions else "OPNsense",
        "board": "OPNsense", "uptime": "", "interfaces": {}, "addresses": [], "rules": [], "iface_lists": {},
        "warnings": [f"{k}: {v}" + (f" — нужно право «{PRIVILEGE_HINTS[k]}»" if k in PRIVILEGE_HINTS and "403" in v else "")
                     for k, v in raw.get("_errors", {}).items() if "404" not in v],
    }
    ident_to_dev = {}
    for i in _rows(raw.get("interfaces")):
        dev = i.get("device") or ""
        if not dev or dev in ("lo0", "enc0", "pflog0", "pfsync0"):
            continue
        if i.get("identifier"):
            ident_to_dev[i["identifier"]] = dev
        desc = i.get("description") or ""
        snap["interfaces"][dev] = {
            "name": dev, "type": "opnsense", "running": i.get("status") == "up",
            "disabled": i.get("enabled") is False, "comment": "" if desc == "Unassigned Interface" else desc,
            "vpn": _device_vpn(dev),
        }
        for a in i.get("ipv4") or []:
            addr = a.get("ipaddr", "")
            if "/" not in addr:
                addr = f"{addr}/{a.get('subnetbits', 32)}"
            try:
                ifc = ipaddress.ip_interface(addr)
            except ValueError:
                continue
            peer = ip_or_none(a.get("endpoint")) if a.get("tunnel") else None
            snap["addresses"].append({
                "ip": str(ifc.ip), "prefix": ifc.network.prefixlen, "cidr": str(ifc.network), "peer": peer,
                "interface": dev, "dynamic": i.get("link_type") == "dhcp", "vpn": _device_vpn(dev),
            })
    snap["ident_to_dev"] = ident_to_dev
    snap["routes"] = _parse_routes(_rows(raw.get("routes")), snap, cfg.max_routes)
    snap["tunnels"] = _parse_tunnels(raw, snap)
    snap["nat"] = _parse_nat(_rows(raw.get("nat")), snap)
    gw_down = [g for g in _rows(raw.get("gateways"))
               if str(g.get("status", "none")) not in ("none", "online") and g.get("address") not in ("~", "")]
    for g in gw_down:
        snap["warnings"].append(f"шлюз {g.get('name')} ({g.get('address')}): {g.get('status_translated') or g.get('status')}")
    snap["tables"] = ["main"]
    ips = {a["ip"] for a in snap["addresses"]} | set(cfg.public_ips)
    if ip_or_none(cfg.host):
        ips.add(ip_or_none(cfg.host))
    snap["ips"] = sorted(ips)
    return snap


def _parse_routes(rows: list[dict], snap: dict, limit: int) -> list[dict]:
    """Таблица ядра FreeBSD (netstat -rn): все записи активны, флаги U/G/S/H, 1/2/3 — протоколы FRR."""
    routes = []
    for r in rows:
        if r.get("proto") != "ipv4" or r.get("netif") == "lo0":
            continue
        dst = "0.0.0.0/0" if r.get("destination") == "default" else norm_net(r.get("destination", ""))
        if not dst:
            continue
        flags = r.get("flags", "")
        gw = r.get("gateway", "")
        iface = r.get("netif") or None
        if "B" in flags or "R" in flags and "G" not in flags:
            proto = "blackhole"
        elif "G" not in flags or gw.startswith("link#"):
            proto = "connected"
        elif any(f in flags for f in "123"):
            proto = "dynamic"  # маршрут от FRR (OSPF/BGP); точный протокол — через os-frr
        else:
            proto = "static"
        hop = {"gateway": ip_or_none(gw), "interface": iface}
        if iface in snap["interfaces"]:
            hop["vpn"] = snap["interfaces"][iface]["vpn"]
        routes.append({
            "id": r.get("id", ""), "dst": dst, "prefix": int(dst.split("/")[1]), "gateway": gw,
            "hops": [hop] if proto != "blackhole" else [], "protocol": proto, "active": True,
            "distance": 0 if proto == "connected" else 1, "table": "main",
            "comment": r.get("intf_description", ""),
        })
    if len(routes) > limit:
        snap["warnings"].append(f"маршрутов {len(routes)}, показаны первые {limit} (max_routes)")
        routes = routes[:limit]
    return routes


def _age_seconds(v) -> float | None:
    """latest-handshake: unix-время (0 — не было) или уже возраст в секундах."""
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return None
    return time.time() - v if v > 10**9 else v


def _parse_tunnels(raw: dict, snap: dict) -> list[dict]:
    tunnels = []
    ifaces = snap["interfaces"]

    # WireGuard: wg show (по строке на интерфейс и на peer)
    names = {s.get("interface") or s.get("device"): s.get("name") for s in _rows(raw.get("wg_servers"))}
    for p in _rows(raw.get("wg_show")):
        if p.get("type", "peer") != "peer":
            continue
        dev = p.get("if") or p.get("interface") or ""
        age = _age_seconds(p.get("latest-handshake-age") or p.get("latest-handshake"))
        up = (ifaces.get(dev) or {}).get("running", True)
        state = "down" if not up or age is None else "up" if age <= 180 else "idle"
        endpoint = (p.get("endpoint") or "").rsplit(":", 1)[0].strip("[]")
        if endpoint in ("(none)", ""):
            endpoint = ""
        allowed = [n for n in (norm_net(x) for x in str(p.get("allowed-ips", "")).replace(" ", ",").split(",") if x) if n]
        t = _tunnel(snap, f"wg:{dev}:{p.get('public-key', '')[:12]}", "wireguard", dev,
                    p.get("name") or names.get(dev) or f"{dev} → {endpoint or 'peer'}", state,
                    remote_public=ip_or_none(endpoint), remote_host=endpoint or None, routed_nets=allowed,
                    details={"рукопожатие": f"{int(age)}s назад" if age else "никогда", "endpoint": p.get("endpoint", ""),
                             "allowed-ips": p.get("allowed-ips", ""), "rx": p.get("transfer-rx", ""),
                             "tx": p.get("transfer-tx", "")})
        t["remote_nets"] += [n for n in allowed if int(n.split("/")[1]) >= 16]
        tunnels.append(t)

    # OpenVPN: сессии (клиенты — ovpnc<id>, серверы — ovpns<id>)
    instances = {str(i.get("vpnid") or i.get("id") or ""): i for i in _rows(raw.get("ovpn_instances"))}
    seen = set()
    for s in _rows(raw.get("ovpn_sessions")):
        role = s.get("type") or ("client" if s.get("is_client") else "server")
        vid = str(s.get("id") or s.get("vpnid") or "")
        dev = f"ovpn{'c' if role == 'client' else 's'}{vid}"
        inst = instances.get(vid, {})
        real = str(s.get("real_address") or s.get("remote_host") or inst.get("remote") or "")
        real_ip = ip_or_none(real.split(":")[0] if real.count(":") == 1 else real)
        connected = str(s.get("status", "")).lower() in ("connected", "ok", "up") or bool(s.get("common_name"))
        label = s.get("description") or inst.get("description") or dev
        if role != "client" and s.get("common_name"):
            label = f"{label} ← {s['common_name']}"
        tid = f"ovpn:{dev}:{s.get('common_name') or ''}"
        seen.add(dev)
        tunnels.append(_tunnel(
            snap, tid, f"ovpn-{role if role in ('client', 'server') else 'client'}", dev if dev in ifaces else None,
            label, "up" if connected and (ifaces.get(dev) or {}).get("running", True) else "down",
            remote_public=real_ip, remote_host=real.split(":")[0] or None,
            details={"статус": s.get("status", ""), "real": real, "virtual": s.get("virtual_address", ""),
                     "с": s.get("connected_since", "")}))
    # интерфейсы OpenVPN, о которых API сессий молчит (нет прав) — хотя бы по устройству
    for dev, i in ifaces.items():
        if i["vpn"] in ("ovpn-client", "ovpn-server") and dev not in seen:
            tunnels.append(_tunnel(snap, f"ovpn:{dev}", i["vpn"], dev, i["comment"] or dev,
                                   "up" if i["running"] else "down",
                                   details={"примечание": "нет данных о сессии (права Status: OpenVPN)"}))

    # IPsec: конфигурация connections/children + состояние phase1
    states = {}
    for p in _rows(raw.get("ipsec_p1")):
        key = p.get("phase1desc") or p.get("name") or ""
        remote = ip_or_none(str(p.get("remote-addrs") or p.get("remote_addrs") or "").split(",")[0])
        states[key] = states[remote] = b(p.get("connected")) or str(p.get("state", "")).upper() == "ESTABLISHED"
    children: dict[str, list] = {}
    for ch in _rows(raw.get("ipsec_child")):
        if str(ch.get("enabled", "1")) == "1":
            children.setdefault(ch.get("connection", ""), []).append(ch)
    for c in _rows(raw.get("ipsec_conn")):
        if str(c.get("enabled", "1")) != "1":
            continue
        remote = ip_or_none(str(c.get("remote_addrs", "")).split(",")[0])
        desc = c.get("description") or remote or c.get("uuid", "")
        chs = children.get(c.get("uuid", ""), [])
        pols = [{"src": norm_net(str(ch.get("local_ts", "")).split(",")[0]) or "0.0.0.0/0",
                 "dst": norm_net(str(ch.get("remote_ts", "")).split(",")[0])} for ch in chs]
        pols = [p for p in pols if p["dst"]]
        up = states.get(desc) or states.get(remote) or False
        tunnels.append(_tunnel(
            snap, f"ipsec:{c.get('uuid', desc)}", "ipsec", None, f"IPsec {desc}", "up" if up else "down",
            remote_public=remote, remote_host=remote or c.get("remote_addrs"),
            local_public=ip_or_none(str(c.get("local_addrs", "")).split(",")[0]),
            routed_nets=list(dict.fromkeys(p["dst"] for p in pols)), policies=pols,
            details={"политики": "; ".join(f"{p['src']} → {p['dst']}" for p in pols)}))

    # GRE / GIF
    for key, kind in (("gre", "gre"), ("gif", "ipip")):
        for g in _rows(raw.get(key)):
            dev = g.get("device") or g.get(f"{key}if") or ""
            remote = ip_or_none(g.get("remote-addr") or g.get("remote_addr"))
            tunnels.append(_tunnel(snap, f"{kind}:{dev}", kind, dev or None, g.get("descr") or dev,
                                   "up" if (ifaces.get(dev) or {}).get("running") else "down",
                                   remote_public=remote, remote_host=remote,
                                   details={"remote": remote or "", "local": g.get("local-addr", "")}))
    return tunnels


def _net_alias(v: str, snap: dict) -> str | None:
    """'any' → None; 'lan' → сеть интерфейса lan; IP/CIDR как есть; прочие алиасы — нераспознаны ('?')."""
    v = (v or "").strip()
    if v in ("", "any"):
        return None
    if v == "lo0":
        return "127.0.0.0/8"
    if norm_net(v):
        return norm_net(v)
    dev = snap["ident_to_dev"].get(v.replace("ip", "")) if v.endswith("ip") else snap["ident_to_dev"].get(v)
    if dev:
        a = next((x for x in snap["addresses"] if x["interface"] == dev), None)
        if a:
            return f"{a['ip']}/32" if v.endswith("ip") else a["cidr"]
    return "?"


def _parse_nat(rows: list[dict], snap: dict) -> list[dict]:
    """Source NAT → формат правил srcnat MikroTik, чтобы трассировка работала одинаково.

    Правило с несколькими источниками ("lan,lo0,127.0.0.0/8") разворачивается в несколько.
    Без target — трансляция в адрес исходящего интерфейса (masquerade).
    """
    rules = []
    for r in rows:
        if str(r.get("enabled", "1")) != "1":
            continue
        if r.get("is_automatic") and (r.get("destination_port") or r.get("source_port")):
            continue  # авто-правила для ISAKMP (порт 500) к маршрутизации отношения не имеют
        out = snap["ident_to_dev"].get(r.get("interface", ""), r.get("interface") or None)
        extra = {}
        for k in ("destination_port", "source_port"):
            if r.get(k):
                extra[k] = r[k]
        if (r.get("protocol") or "any") != "any":
            extra["protocol"] = r["protocol"]
        dst = _net_alias(r.get("destination_net", ""), snap)
        if dst == "?":
            extra["destination_net"] = r.get("destination_net")
        target = (r.get("target") or "").strip()
        if b(r.get("nonat")) or b(r.get("no_nat")):
            action, to = "accept", None
        elif not target or target.endswith("ip"):
            action, to = "masquerade", None
        else:
            action, to = "src-nat", (norm_net(target) or target).split("/")[0]
        for src in [s for s in str(r.get("source_net") or "any").split(",")] or ["any"]:
            snet = _net_alias(src, snap)
            e = dict(extra)
            if snet == "?":
                e["source_net"] = src
            rules.append({
                "id": r.get("description") or r.get("uuid", "")[:8], "action": action, "to_addresses": to,
                "comment": r.get("description", ""), "src": None if snet in (None, "?") else snet, "src_neg": b(r.get("source_not")),
                "dst": None if dst in (None, "?") else dst, "dst_neg": b(r.get("destination_not")),
                "out_interface": out, "out_interface_neg": False, "out_list": None, "out_list_neg": False,
                "ipsec_policy": None, "extra": e,
            })
    return rules

