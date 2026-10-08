"""Base comum das alterações administrativas: a tela do admin e a API chamam os mesmos serviços.

Cada serviço valida, altera a sessão (sem commit) e devolve um Outcome com a mensagem, o objeto alterado, os registros
de auditoria e o que só pode acontecer depois do commit (convites por e-mail, avisos). Quem chamou decide o autor da
auditoria, faz o commit e dispara os envios — assim a regra é uma só e a simulação (dry_run) nunca envia nada.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


class ServiceError(ValueError):
    """Regra de negócio violada (422 na API). Mensagem em português, a mesma mostrada na tela."""
    status = 422

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        if status is not None:
            self.status = status


class Conflict(ServiceError):
    """Conflito com o estado atual (409 na API): nome duplicado, item em uso etc."""
    status = 409


@dataclass
class Outcome:
    message: str = ""
    obj: object = None
    tenant_id: int | None = None
    audit: list = field(default_factory=list)  # [(ação, alvo, detalhes)]
    invites: list = field(default_factory=list)  # [(User, token)] — enviar depois do commit
    after_commit: list = field(default_factory=list)  # [callable] — avisos que só saem depois do commit
    warning: str = ""


def clean(v, n: int = 160) -> str:
    return re.sub(r"\s+", " ", str(v or "")).strip()[:n]


def clean_list(values, n: int = 60, item_len: int = 120, lower: bool = False) -> list[str]:
    out: list[str] = []
    for x in values or []:
        x = clean(x, item_len)
        if lower:
            x = x.lower()
        if x and x not in out:
            out.append(x)
    return out[:n]


def diff(before: dict, after: dict) -> dict:
    """Campos que mudaram, no formato da auditoria: {campo: [antes, depois]}."""
    return {k: [str(before.get(k)), str(after.get(k))] for k in after if before.get(k) != after.get(k)}
