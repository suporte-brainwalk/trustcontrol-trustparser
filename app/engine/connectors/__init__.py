"""Conectores API PULL: coletam eventos de produtos SaaS de segurança e entregam linhas JSON aos parsers builtin.

Uso: `from app.engine.connectors import get, REGISTRY` → `get("cortex-xdr").pull(config, secrets, cursor)`.
"""
from .base import REGISTRY, Connector, ConnectorError, Field, PullResult, get  # noqa: F401
from . import axur, cortex_xdr, tenable, vision_one, watchguard_epdr, withsecure  # noqa: F401,E402

__all__ = ["REGISTRY", "Connector", "ConnectorError", "Field", "PullResult", "get"]
