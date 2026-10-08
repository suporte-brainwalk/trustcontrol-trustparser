"""Configurações editáveis no portal (tabela settings)."""
from ..db import Session, utcnow
from ..models import Setting

DEFAULTS = {
    "test_mode": False,
    "test_allowlist": ["rogerio.crispim@brainwalk.com.br", "suporte.trustcontrol@brainwalk.com.br"],
    "session_idle_minutes": 30,
    "require_mfa_admin": True,
    # buffer (decisão 08/10/2026): 2 h; o que não foi entregue fica até 24 h; limite de disco
    "buffer_hours": 2,
    "undelivered_max_hours": 24,
    "buffer_max_mb": 8000,
    "upload_retention_hours": 2,
    # avisos operacionais (N7): destinatários escolhidos na tela + administradores
    "ops_recipients": ["suporte.trustcontrol@brainwalk.com.br"],
    "ops_include_admins": True,
    "dest_fail_threshold": 5,
    "drift_threshold_pct": 20,
    "drift_alerted": {},
    "studio_mask_default": True,
    "ai_spend_usd": 0.0,
    # e-mail de administrador -> caixa que recebe os avisos no lugar
    "alert_redirects": {"rogerio.crispim@brainwalk.com.br": "suporte.trustcontrol@brainwalk.com.br"},
}


def get(key, session=None):
    s = session or Session()
    row = s.get(Setting, key)
    if row is None:
        return DEFAULTS.get(key)
    return row.value.get("v")


def set_(key, value, session=None):
    s = session or Session()
    row = s.get(Setting, key)
    if row is None:
        s.add(Setting(key=key, value={"v": value}, updated_at=utcnow()))
    else:
        row.value = {"v": value}
        row.updated_at = utcnow()


def all_(session=None):
    return {k: get(k, session) for k in DEFAULTS}
