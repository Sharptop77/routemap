# MikroTik Route Map

[Русский](README.md) | **English**

A web application that polls MikroTik routers (and OPNsense) over their APIs and draws a routing map
that takes active VPN tunnels into account.

## Features

- **API polling**: RouterOS 7 REST API (`rest`/`http`) or the classic API (`api` on 8728, `api-ssl` on 8729), which also works with RouterOS 6; **OPNsense** via its REST API (`opnsense`).
- **VPN**: WireGuard (each peer is a separate tunnel; state from `last-handshake`: up / idle / down),
  L2TP / SSTP / PPTP / OpenVPN — both client and server side (`/ppp active`), GRE / IPIP / EoIP,
  site-to-site IPsec (policy-based; networks come from tunnel policies), and a "+ IPsec" mark for L2TP/GRE over IPsec.
- **Tunnel matching across routers**: the two ends of one tunnel are merged into a single edge
  using transit addresses (PPP point-to-point address, WireGuard `allowed-address`, a shared /30) and public IPs.
  Tunnels to hosts that are not polled are drawn as a "remote side" diamond.
- **Routes**: static / OSPF / BGP / RIP / blackhole, ECMP, all routing tables (`routing-table`/`routing-mark`).
  A route that leaves through a VPN interface is bound to the specific tunnel (for WireGuard, to the peer chosen by allowed-address).
  If the next router already knows the network itself, the route is attached to the tunnel (shown in details as "N routes") instead of drawing duplicate arrows.
- **Trace**: "where does a packet to X go" — longest-prefix match over active routes, `/routing rule`
  (src/dst), srcnat (masquerade / src-nat / netmap) before IPsec policies are checked, IPsec policies,
  hops between polled routers, loop and blackhole detection.
- Filters by table and protocol, "only networks behind VPN", auto-refresh; manual node layout is remembered in the browser.

## Running

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp config.example.yaml config.yaml   # edit it
MT_PASSWORD=... .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8080
```

Without `config.yaml` (or with `ROUTEMAP_DEMO=1`) a demo lab with three routers plus one unreachable router starts.

Docker:

```bash
MT_PASSWORD=... docker compose up -d --build
```

Optional Basic auth for the web UI: set `ROUTEMAP_USER` and `ROUTEMAP_PASSWORD`.

## Read-only user on MikroTik

```
/user group add name=routemap policy=read,api,rest-api,!write,!policy,!sensitive,!ftp,!ssh,!telnet,!winbox,!web,!reboot,!test,!sniff,!romon
/user add name=routemap group=routemap password=STRONG_PASSWORD address=MAP_SERVER_IP
```

REST needs the `www-ssl` service enabled (or `www` for `transport: http`); the classic API needs `api` / `api-ssl`.
Restrict `address=` in `/ip service` to the map server. On RouterOS 6 use `transport: api` (there is no `rest-api` policy there — remove it from the group).

## OPNsense

`transport: opnsense` polls the OPNsense REST API (HTTPS, the GUI port). In the config, `username` is the API key and `password` is the API secret.
No plugins are needed for reading (WireGuard is built in since 24.1, before that use `os-wireguard`; `os-frr` only if you run OSPF/BGP).

1. System → Access → Users → create a user (e.g. `routemap`) without shell access.
2. Effective Privileges — only the pages you need:
   `Diagnostics: Routes`, `Interfaces: Overview`, `System: Gateways`, `Firewall: Source NAT`,
   `VPN: WireGuard`, `VPN: IPsec: Connections`, `Status: IPsec`, `Status: OpenVPN`, `VPN: OpenVPN: Instances`,
   `Interfaces: Other Types: GRE` / `GIF`, `Dashboard (all)` (hostname and version).
3. API keys → "+" → `apikey.txt` with key/secret.
4. Allow HTTPS to the GUI from the map server (preferably from its IP only).

Missing privileges are shown on the "Routers" tab: a section that returned 403 is labelled with the privilege it needs.
Limitations: policy routing via firewall rules is not readable through the API; outbound NAT is limited to what
`firewall/source_nat` returns (rules with ports/aliases are marked as not evaluated in the trace);
FRR routes are shown with protocol `dynamic`.

## API

| method | description |
|---|---|
| `GET /api/topology?refresh=1&tables=main,vpn&protocols=static,ospf&inactive=0&default=1` | graph (nodes/edges), tunnels, routers |
| `GET /api/trace?router=hq&dst=192.168.30.15&src=192.168.10.200&table=` | trace |
| `GET /api/router/{name}` | normalized router snapshot (routes, tunnels, rules, NAT) |
| `/api/docs` | Swagger |

## Limitations

- IPv4 only.
- The trace does not evaluate mangle (`routing-mark` set by firewall), the incoming interface in rules, dstnat or firewall filters;
  srcnat rules whose conditions cannot be checked from addresses alone (ports, protocol, address lists) are reported as not evaluated.
- For full-view BGP, limit `max_routes` — the whole table is still downloaded.
- JS libraries (cytoscape, fcose) are loaded from a CDN; for an isolated network, download them into `static/` and fix the paths in `index.html`.

## Layout

```
app/mikrotik.py   — transport (REST/API), parsing into a snapshot, tunnel discovery
app/opnsense.py   — OPNsense driver (REST API → the same snapshot)
app/topology.py   — tunnel matching, graph, trace (incl. srcnat)
app/demo.py       — demo lab (raw data in RouterOS v6/v7 format)
app/main.py       — FastAPI
static/           — frontend (Cytoscape.js)
tests/            — pytest on demo and synthetic data
```
