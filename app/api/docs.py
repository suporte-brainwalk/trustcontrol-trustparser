"""Documentação interativa (Swagger UI servido localmente) em /api/docs.

A página em si é só a interface — não contém dados. A especificação (/api/v1/openapi.json) exige administrador logado
ou uma chave de API válida, informada na própria página (a chave fica só na memória da aba).
"""
from __future__ import annotations

from flask import Blueprint, current_app, redirect, render_template, url_for
from flask_login import current_user

docs_bp = Blueprint("api_docs", __name__, url_prefix="/api")
SWAGGER_VERSION = "5.33.0"


@docs_bp.get("/")
@docs_bp.get("")
def root():
    return redirect(url_for("api_docs.docs"))


@docs_bp.get("/docs")
def docs():
    is_admin = current_user.is_authenticated and getattr(current_user, "role", "") == "admin"
    return render_template("api/docs.html", swagger=SWAGGER_VERSION, is_admin=is_admin,
                           api_base=current_app.config["APP_BASE_URL"].rstrip("/") + "/api/v1")
