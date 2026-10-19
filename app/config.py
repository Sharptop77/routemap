"""Загрузка config.yaml с подстановкой переменных окружения ${VAR} / ${VAR:-default}."""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field, fields
from pathlib import Path

import yaml

from . import demo
from .mikrotik import RouterConfig

log = logging.getLogger(__name__)


@dataclass
class AppConfig:
    routers: list[RouterConfig] = field(default_factory=list)
    cache_ttl: float = 30.0     # сколько секунд отдавать данные из кэша
    min_refresh: float = 5.0    # не опрашивать роутеры чаще (даже при "Обновить")
    demo: bool = False
    auth_user: str = ""
    auth_password: str = ""


def _expand(text: str) -> str:
    return re.sub(r"\$\{(\w+)(?::-([^}]*))?\}", lambda m: os.environ.get(m[1], m[2] or ""), text)


def load_config(path: str | None = None) -> AppConfig:
    path = path or os.environ.get("ROUTEMAP_CONFIG", "config.yaml")
    auth = dict(auth_user=os.environ.get("ROUTEMAP_USER", ""), auth_password=os.environ.get("ROUTEMAP_PASSWORD", ""))
    if os.environ.get("ROUTEMAP_DEMO", "").lower() in ("1", "true", "yes") or not Path(path).exists():
        log.warning("config %s не найден или ROUTEMAP_DEMO=1 — демо-режим", path)
        return AppConfig(routers=demo.ROUTERS, demo=True, **auth)

    data = yaml.safe_load(_expand(Path(path).read_text())) or {}
    if data.get("demo"):
        return AppConfig(routers=demo.ROUTERS, demo=True, **auth)
    known = {f.name for f in fields(RouterConfig)} - {"demo"}
    defaults = data.get("defaults", {})
    routers = []
    for r in data.get("routers", []):
        r = {**defaults, **r}
        unknown = set(r) - known
        if unknown:
            log.warning("router %s: неизвестные поля %s", r.get("name"), unknown)
        r = {k: v for k, v in r.items() if k in known}
        for k in ("username", "password"):  # пустая ${VAR} даёт в YAML null
            r[k] = "" if r.get(k) is None else str(r.get(k))
        r.setdefault("name", r.get("host"))
        routers.append(RouterConfig(**r))
    if not routers:
        raise SystemExit(f"{path}: список routers пуст")
    names = [r.name for r in routers]
    if len(set(names)) != len(names):
        raise SystemExit(f"{path}: имена роутеров должны быть уникальны")
    return AppConfig(
        routers=routers,
        cache_ttl=float(data.get("cache_ttl", 30)),
        min_refresh=float(data.get("min_refresh", 5)),
        auth_user=auth["auth_user"] or str(data.get("auth", {}).get("user", "")),
        auth_password=auth["auth_password"] or str(data.get("auth", {}).get("password", "")),
    )
