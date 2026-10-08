"""Paginação por cursor opaco (ordem estável por coluna + id)."""
from __future__ import annotations

import base64
import json
from datetime import datetime

from sqlalchemy import and_, or_

from .errors import ApiError

MAX_LIMIT, DEFAULT_LIMIT = 200, 50


def encode(value, row_id: int) -> str:
    v = value.isoformat() if isinstance(value, datetime) else value
    return base64.urlsafe_b64encode(json.dumps({"v": v, "id": row_id}, separators=(",", ":")).encode()).decode().rstrip("=")


def decode(cursor: str) -> tuple:
    try:
        d = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
        v = d["v"]
        if isinstance(v, str):
            try:
                v = datetime.fromisoformat(v)
            except ValueError:
                pass
        return v, int(d["id"])
    except Exception as e:  # noqa: BLE001
        raise ApiError(400, "cursor inválido") from e


def page(session, q, col, id_col, limit: int, cursor: str | None, desc: bool = True):
    """Aplica ordem (col, id) e o cursor; devolve (itens, next_cursor)."""
    if cursor:
        v, last_id = decode(cursor)
        cond = or_(col < v, and_(col == v, id_col < last_id)) if desc else or_(col > v, and_(col == v, id_col > last_id))
        q = q.where(cond)
    q = q.order_by(col.desc(), id_col.desc()) if desc else q.order_by(col.asc(), id_col.asc())
    rows = session.execute(q.limit(limit + 1)).scalars().all()
    nxt = None
    if len(rows) > limit:
        rows = rows[:limit]
        last = rows[-1]
        nxt = encode(getattr(last, col.key), last.id)
    return rows, nxt
