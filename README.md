# MikroTik Route Map

**Русский** | [English](README.en.md)

Веб-приложение, которое опрашивает маршрутизаторы MikroTik (и OPNsense) по API и рисует карту маршрутов
с учётом поднятых VPN-туннелей.

## Что умеет

- **Опрос по API**: REST API RouterOS 7 (`rest`/`http`) или классический API (`api` 8728, `api-ssl` 8729) — подходит и для RouterOS 6; **OPNsense** — через его REST API (`opnsense`).
- **VPN**: WireGuard (каждый peer — отдельный туннель, состояние по `last-handshake`: up / idle / down),
  L2TP / SSTP / PPTP / OpenVPN — и клиент, и сервер (`/ppp active`), GRE / IPIP / EoIP,
  IPsec site-to-site (policy-based, сети берутся из tunnel-политик), пометка «+ IPsec» для L2TP/GRE поверх IPsec.
- **Сопоставление туннелей между роутерами**: две стороны одного туннеля склеиваются в одно ребро
  по транзитным адресам (p2p-адрес PPP, `allowed-address` WireGuard, общая /30) и публичным IP.
  Туннели к неопрашиваемым узлам показываются ромбом «удалённая сторона».
- **Маршруты**: static / OSPF / BGP / RIP / blackhole, ECMP, все таблицы маршрутизации (`routing-table`/`routing-mark`).
  Маршрут, уходящий в VPN-интерфейс, привязывается к конкретному туннелю (для WireGuard — к peer'у по allowed-address).
  Если следующий роутер сам знает сеть, маршрут «вешается» на туннель (видно в деталях: «N маршр.»), без дублирующих стрелок.
- **Трассировка**: «куда пойдёт пакет на X» — longest-prefix match по активным маршрутам, `/routing rule`
  (src/dst), srcnat (masquerade / src-nat / netmap) до проверки IPsec-политик, IPsec-политики, переход между опрашиваемыми роутерами, обнаружение петель и blackhole.
- Фильтры по таблицам и протоколам, «только сети за VPN», автообновление, ручная раскладка запоминается в браузере.

## Запуск

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp config.example.yaml config.yaml   # отредактировать
MT_PASSWORD=... .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8080
```

Без `config.yaml` (или с `ROUTEMAP_DEMO=1`) запускается демо со стендом из трёх роутеров и одного недоступного.

Docker:

```bash
MT_PASSWORD=... docker compose up -d --build
```

## Пользователь на MikroTik (только чтение)

```
/user group add name=routemap policy=read,api,rest-api,!write,!policy,!sensitive,!ftp,!ssh,!telnet,!winbox,!web,!reboot,!test,!sniff,!romon
/user add name=routemap group=routemap password=СЛОЖНЫЙ_ПАРОЛЬ address=IP_СЕРВЕРА_КАРТЫ
```

Для REST нужен включённый сервис `www-ssl` (или `www` для `transport: http`), для API — `api` / `api-ssl`.
Ограничьте `address=` в `/ip service` адресом сервера карты. На RouterOS 6 используйте `transport: api` (политики `rest-api` там нет — уберите её из группы).

## OPNsense

`transport: opnsense` — опрос через REST API OPNsense (HTTPS, порт GUI). В конфиге `username` — API key, `password` — API secret.
Плагины для чтения не нужны (WireGuard встроен с 24.1, до этого — `os-wireguard`; `os-frr` — только если есть OSPF/BGP).

1. System → Access → Users → создать пользователя (например, `routemap`), без shell.
2. Effective Privileges — только нужные страницы:
   `Diagnostics: Routes`, `Interfaces: Overview`, `System: Gateways`, `Firewall: Source NAT`,
   `VPN: WireGuard`, `VPN: IPsec: Connections`, `Status: IPsec`, `Status: OpenVPN`, `VPN: OpenVPN: Instances`,
   `Interfaces: Other Types: GRE` / `GIF`, `Dashboard (all)` (имя хоста и версия).
3. API keys → «+» → `apikey.txt` с key/secret.
4. Разрешить HTTPS к GUI с сервера карты (лучше только с его IP).

Каких прав не хватает, видно на вкладке «Роутеры»: раздел с ответом 403 помечается нужной привилегией.
Ограничения: маршрутизация по правилам firewall (policy routing) через API не читается; outbound NAT — только
то, что отдаёт `firewall/source_nat` (правила с портами/алиасами помечаются в трассировке как неучтённые);
у FRR-маршрутов протокол показывается как `dynamic`.

## API

| метод | описание |
|---|---|
| `GET /api/topology?refresh=1&tables=main,vpn&protocols=static,ospf&inactive=0&default=1` | граф (узлы/рёбра), туннели, роутеры |
| `GET /api/trace?router=hq&dst=192.168.30.15&src=192.168.10.200&table=` | трассировка |
| `GET /api/router/{name}` | нормализованный снимок роутера (маршруты, туннели, правила, NAT) |
| `/api/docs` | Swagger |

## Ограничения

- Только IPv4.
- Трассировка не учитывает mangle (`routing-mark` из firewall), входящий интерфейс в правилах, dstnat и фильтры firewall;
  srcnat-правила с условиями, которые по адресам не проверить (порты, протокол, address-list), помечаются как неучтённые.
- Для full-view BGP ограничьте `max_routes` — таблица всё равно выкачивается целиком.
- JS-библиотеки (cytoscape, fcose) грузятся с CDN; для изолированной сети скачайте их в `static/` и поправьте пути в `index.html`.

## Структура

```
app/mikrotik.py   — транспорт (REST/API), парсинг в снимок, разбор туннелей
app/opnsense.py   — драйвер OPNsense (REST API → тот же снимок)
app/topology.py   — сопоставление туннелей, граф, трассировка (с учётом srcnat)
app/demo.py       — демо-стенд (сырые данные в формате RouterOS v6/v7)
app/main.py       — FastAPI
static/           — фронтенд (Cytoscape.js)
tests/            — pytest на демо- и синтетических данных
```
