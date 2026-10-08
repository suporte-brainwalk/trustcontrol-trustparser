"""Pessoas com acesso ao portal: administradores (Trust) e usuários de tenant (gestor/leitor). Convite por magic link."""
from __future__ import annotations

import re

from sqlalchemy import func, select

from ..db import Session
from ..models import Tenant, User
from . import auth as authsvc
from .changes import Outcome, ServiceError

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")
ROLES = {"manager": "Gestor", "reader": "Leitor"}
ROLE_LABEL = {"admin": "Administrador", "manager": "Gestor", "reader": "Leitor"}


class PeopleError(ServiceError):
    pass


def norm_email(v) -> str | None:
    v = (v or "").strip().lower()
    return v if EMAIL_RE.match(v) and len(v) <= 254 else None


def list_people(t: Tenant) -> list[User]:
    return Session.execute(select(User).where(User.tenant_id == t.id).order_by(User.role, User.name)).scalars().all()


def _new_user(email, name, role, tenant_id, out: Outcome) -> User:
    if Session.execute(select(User.id).where(User.email == email)).first():
        raise PeopleError(f"{email} já tem acesso ao Trust Parser (o acesso é único por e-mail).", 409)
    u = User(email=email, name=(name or email.split("@")[0])[:160], role=role, tenant_id=tenant_id, status="invited")
    Session.add(u)
    Session.flush()
    out.invites.append((u, authsvc.create_magic_link(u, "invite", 24 * 60, "")))
    out.audit.append(("user.invited", email, {"role": role}))
    return u


def add(t: Tenant, *, name, email, role=None, access=None, receives=None) -> Outcome:
    """role (tela/API) ou access (EVA) = manager | reader. `receives` existe só por compatibilidade (sem lista de e-mails aqui)."""
    role = role or access
    email = norm_email(email)
    if not email:
        raise PeopleError("Informe um e-mail válido.")
    if role not in ROLES:
        raise PeopleError("Perfil inválido (gestor ou leitor).")
    out = Outcome(message=f"Convite enviado para {email}.", tenant_id=t.id)
    out.obj = _new_user(email, name, role, t.id, out)
    return out


def update(t: Tenant, email: str, *, role=None, name=None, actor: User | None = None) -> Outcome:
    u = Session.execute(select(User).where(User.tenant_id == t.id, User.email == norm_email(email))).scalar_one_or_none()
    if u is None:
        raise PeopleError("Pessoa não encontrada neste tenant.", 404)
    out = Outcome(message=f"{u.email} atualizado(a).", tenant_id=t.id, obj=u)
    if role and role != u.role:
        if role not in ROLES:
            raise PeopleError("Perfil inválido.")
        if actor is not None and actor.id == u.id:
            raise PeopleError("Você não pode alterar o próprio perfil.")
        out.audit.append(("user.role_changed", u.email, {"de": u.role, "para": role}))
        u.role = role
    if name:
        u.name = name.strip()[:160]
    return out


def remove(t: Tenant, email: str, actor: User | None = None) -> Outcome:
    u = Session.execute(select(User).where(User.tenant_id == t.id, User.email == norm_email(email))).scalar_one_or_none()
    if u is None:
        raise PeopleError("Pessoa não encontrada neste tenant.", 404)
    if actor is not None and actor.id == u.id:
        raise PeopleError("Você não pode remover o próprio acesso.")
    Session.delete(u)
    return Outcome(message=f"{email} removido(a).", tenant_id=t.id, audit=[("user.removed", email, {})])


def resend_invite(u, email: str | None = None) -> Outcome:
    if isinstance(u, Tenant):  # chamada da EVA: (tenant, email)
        u = Session.execute(select(User).where(User.tenant_id == u.id, User.email == norm_email(email))).scalar_one_or_none()
        if u is None:
            raise PeopleError("Pessoa não encontrada neste tenant.", 404)
    if u.status != "invited":
        raise PeopleError("Esta pessoa já ativou o acesso; ela entra pela tela de login.")
    out = Outcome(message=f"Novo convite enviado para {u.email}.", tenant_id=u.tenant_id)
    out.invites.append((u, authsvc.create_magic_link(u, "invite", 24 * 60, "")))
    out.audit.append(("user.invite_resent", u.email, {}))
    return out


# ------------------------------------------------------------------------------------------------ administradores
def admins() -> list[User]:
    return Session.execute(select(User).where(User.role == "admin").order_by(User.status, User.name)).scalars().all()


def add_admin(*, name, email) -> Outcome:
    email = norm_email(email)
    if not email:
        raise PeopleError("Informe um e-mail válido.")
    out = Outcome(message=f"Convite de administrador enviado para {email}.")
    out.obj = _new_user(email, name, "admin", None, out)
    return out


def set_admin_status(u: User, status: str, actor: User) -> Outcome:
    if u.role != "admin":
        raise PeopleError("Não é administrador.")
    if u.id == actor.id:
        raise PeopleError("Você não pode suspender ou remover a si mesmo(a).")
    if status not in ("active", "suspended", "removed"):
        raise PeopleError("Situação inválida.")
    authsvc.assert_not_last_admin(u)
    if status == "removed":
        Session.delete(u)
        return Outcome(message=f"Administrador {u.email} removido.", audit=[("admin.removed", u.email, {})])
    u.status = status
    return Outcome(message=f"Administrador {u.email} {'suspenso' if status == 'suspended' else 'reativado'}.",
                   audit=[("admin." + status, u.email, {})])


def count_users(tenant_id: int) -> int:
    return Session.execute(select(func.count()).select_from(User).where(User.tenant_id == tenant_id)).scalar_one()
