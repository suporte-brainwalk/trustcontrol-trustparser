"""Segredos de destinos e conectores: AES-256-GCM com chave mestra fora do banco (SECRETS_KEY no .env).

O valor só é decifrado no momento do envio/coleta. A tela e a API nunca devolvem segredos — só "cadastrado em … por …".
"""
from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app

VERSION = b"\x01"


class SecretsError(ValueError):
    pass


def _key() -> bytes:
    raw = current_app.config.get("SECRETS_KEY") or ""
    try:
        k = base64.b64decode(raw)
    except ValueError as e:
        raise SecretsError("SECRETS_KEY inválida") from e
    if len(k) != 32:
        raise SecretsError("SECRETS_KEY ausente ou com tamanho errado (precisa de 32 bytes em base64)")
    return k


def seal(data: dict, aad: str) -> bytes:
    """Cifra um dicionário de segredos. `aad` amarra o segredo ao registro (ex.: 'dest:12') — não dá para trocar de lugar."""
    nonce = os.urandom(12)
    ct = AESGCM(_key()).encrypt(nonce, json.dumps(data, separators=(",", ":")).encode(), aad.encode())
    return VERSION + nonce + ct


def open_(blob: bytes | None, aad: str) -> dict:
    if not blob:
        return {}
    if blob[:1] != VERSION:
        raise SecretsError("formato de segredo desconhecido")
    try:
        return json.loads(AESGCM(_key()).decrypt(blob[1:13], blob[13:], aad.encode()))
    except Exception as e:  # noqa: BLE001 — InvalidTag etc.: nunca expor detalhes
        raise SecretsError("não foi possível decifrar o segredo (chave mestra trocada ou registro adulterado)") from e


def merge(blob: bytes | None, aad: str, updates: dict) -> bytes:
    """Atualiza só os campos informados (vazio = mantém o atual)."""
    cur = open_(blob, aad) if blob else {}
    for k, v in (updates or {}).items():
        if v not in (None, ""):
            cur[k] = v
    return seal(cur, aad)
