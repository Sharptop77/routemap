"""HTTP API + раздача фронтенда.  Запуск:  uvicorn app.main:app --host 0.0.0.0 --port 8080"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import logging
import secrets
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles

from . import demo, opnsense, topology
from .config import load_config
from .mikrotik import RouterConfig, collect, error_snapshot, parse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("routemap")

cfg = load_config()
app = FastAPI(title="MikroTik Route Map", docs_url="/api/docs")
_cache: dict = {"ts": 0.0, "snaps": None}
_lock = asyncio.Lock()


@app.middleware("http")
async def basic_auth(request: Request, call_next):
    if cfg.auth_user:
        ok = False
        h = request.headers.get("authorization", "")
        if h.startswith("Basic "):
            try:
                user, _, pwd = base64.b64decode(h[6:]).decode().partition(":")
                ok = secrets.compare_digest(user, cfg.auth_user) and secrets.compare_digest(pwd, cfg.auth_password)
            except ValueError:
                pass
        if not ok:
            return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="routemap"'})
    return await call_next(request)


def _poll(r: RouterConfig) -> dict:
    t0 = time.monotonic()
    try:
        if r.demo:
            snap = parse(r, demo.raw_for(r.name))
        elif r.transport == "opnsense":
            snap = opnsense.parse(r, opnsense.collect(r))
        else:
            snap = parse(r, collect(r))
    except Exception as e:  # noqa: BLE001
        log.warning("%s (%s): %s", r.name, r.host, e)
        snap = error_snapshot(r, e)
    snap["poll_ms"] = int((time.monotonic() - t0) * 1000)
    return snap


async def snapshots(force: bool = False) -> list[dict]:
    def fresh(limit):
        return _cache["snaps"] is not None and time.time() - _cache["ts"] < limit

    if fresh(cfg.min_refresh if force else cfg.cache_ttl):
        return _cache["snaps"]
    async with _lock:
        if not fresh(cfg.min_refresh if force else cfg.cache_ttl):
            snaps = await asyncio.gather(*(asyncio.to_thread(_poll, r) for r in cfg.routers))
            _cache.update(ts=time.time(), snaps=list(snaps))
    return _cache["snaps"]


def _csv(v: str | None) -> set[str] | None:
    return {x for x in v.split(",") if x} if v else None


@app.get("/api/topology")
async def api_topology(refresh: bool = False, tables: str | None = None, protocols: str | None = None,
                       inactive: bool = True, default: bool = True, down_peers: bool = False):
    snaps = await snapshots(refresh)
    data = topology.build(snaps, tables=_csv(tables), protocols=_csv(protocols), inactive=inactive, default=default,
                          down_peers=down_peers)
    data.update(updated=_cache["ts"], demo=cfg.demo, protocols=list(topology.ALL_PROTOCOLS))
    return data


@app.get("/api/trace")
async def api_trace(router: str, dst: str, src: str | None = None, table: str | None = None):
    for v in (dst, src):
        if v:
            try:
                ipaddress.IPv4Address(v)
            except ValueError:
                raise HTTPException(400, f"некорректный IPv4: {v}")
    return topology.trace(await snapshots(), router, dst, src or None, table or None)


@app.get("/api/router/{name}")
async def api_router(name: str):
    snap = next((s for s in await snapshots() if s["name"] == name), None)
    if snap is None:
        raise HTTPException(404, "нет такого роутера")
    return snap


@app.get("/api/health")
async def health():
    return {"ok": True, "routers": len(cfg.routers), "demo": cfg.demo}


app.mount("/", StaticFiles(directory=Path(__file__).parent.parent / "static", html=True), name="static")
