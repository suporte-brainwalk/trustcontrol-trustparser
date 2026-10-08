"""Execução do agente em container isolado: sem segredos do Trust Parser, sem banco, sem Docker, rede só openrouter.ai.

O harness é o CLI `claude` do servidor (montado somente leitura) apontado para o endpoint compatível do OpenRouter
(ANTHROPIC_BASE_URL=https://openrouter.ai/api) com a chave dedicada da EVA e o modelo configurado. A chave entra só
por arquivo de ambiente temporário (600, apagado ao fim), nunca em linha de comando.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time

from . import config, openrouter

log = logging.getLogger("eva.sandbox")
OPT_DIR = os.path.join(config.STATE_DIR, "sandbox-opt")


class SandboxError(RuntimeError):
    pass


# ---------------- acesso à IA (chave dedicada no OpenRouter)
def token_status() -> tuple[bool, int | None]:
    """(acesso ok, None). A chave do OpenRouter não vence por tempo; o saldo do limite é vigiado no heartbeat."""
    if not config.openrouter_key():
        return False, None
    st = openrouter.key_status()
    return bool(st.get("ok")), None


def refresh_if_needed(min_minutes: int = 15) -> tuple[bool, int | None]:  # noqa: ARG001 — assinatura mantida (heartbeat)
    return token_status()


def sandbox_env(key: str, model: str, proxy: str) -> dict:
    """Variáveis do agente no sandbox (o arquivo temporário recebe só as que contêm segredo)."""
    return {
        "ANTHROPIC_BASE_URL": config.OPENROUTER_BASE,
        "ANTHROPIC_AUTH_TOKEN": key,
        "ANTHROPIC_API_KEY": "",
        "ANTHROPIC_MODEL": model,
        "ANTHROPIC_DEFAULT_OPUS_MODEL": model,
        "ANTHROPIC_DEFAULT_SONNET_MODEL": model,
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": model,
        "ANTHROPIC_SMALL_FAST_MODEL": model,
        "CLAUDE_CODE_SUBAGENT_MODEL": model,
        "HOME": "/home/eva",
        "HTTPS_PROXY": proxy, "https_proxy": proxy, "NO_PROXY": "", "no_proxy": "",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_AUTOUPDATER": "1", "DISABLE_TELEMETRY": "1",
        "DISABLE_ERROR_REPORTING": "1", "DISABLE_BUG_COMMAND": "1", "CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY": "1",
    }


# ---------------- sandbox
def prepare_opt():
    os.makedirs(OPT_DIR, exist_ok=True)
    for src in (os.path.join(config.APP_DIR, "sandbox", "guard.py"), os.path.join(config.APP_DIR, "sandbox", "settings.json"),
                os.path.join(config.APP_DIR, "orchestrator", "paths.py")):
        shutil.copy2(src, os.path.join(OPT_DIR, os.path.basename(src)))
    os.makedirs(config.SANDBOX_HOME, exist_ok=True)
    subprocess.run(["chown", "-R", "10001:10001", config.SANDBOX_HOME], check=False)


def build_cmd(name: str, envfile: str, prompt: str, *, system: str, schema: dict, request_dir: str, write: bool, tools: str,
              model: str, session_id: str | None) -> list[str]:
    cmd = ["docker", "run", "--rm", "--name", name, "--network", config.SANDBOX_NETWORK,
           "--user", "10001:10001", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "512",
           "--memory", "4g", "--read-only", "--tmpfs", "/tmp:rw,size=512m",
           "--env-file", envfile,
           "-v", f"{os.path.realpath(config.CLAUDE_BIN)}:/usr/local/bin/claude:ro",
           "-v", f"{config.SANDBOX_HOME}:/home/eva",
           "-v", f"{OPT_DIR}:/opt/eva:ro",
           "-v", f"{config.WORK_REPO}:/work/repo:{'rw' if write else 'ro'}",
           "-v", f"{request_dir}:/work/pedido:ro",
           "-w", "/work/repo", config.SANDBOX_IMAGE,
           "claude", "-p", prompt, "--model", model, "--output-format", "json", "--json-schema", json.dumps(schema),
           "--settings", "/opt/eva/settings.json", "--tools", tools, "--restricted", "--add-dir", "/work/pedido",
           "--permission-mode", "acceptEdits" if write else "dontAsk", "--permission-prompts", "none",
           "--append-system-prompt", system]
    if session_id:
        cmd += ["--resume", session_id]
    return cmd


def run_claude(prompt: str, *, system: str, schema: dict, request_dir: str, write: bool, session_id: str | None = None,
               timeout: int = 1800, tools: str | None = None, web_search: bool = False) -> dict:  # noqa: ARG001
    """Roda o agente (`claude -p`) no sandbox e devolve {structured, session_id, cost, is_error, result}.
    web_search é ignorado: a EVA não pesquisa na web (o proxy só libera openrouter.ai)."""
    prepare_opt()
    key = config.openrouter_key()
    if not key:
        raise SandboxError("chave da IA não configurada no servidor")
    if write:
        subprocess.run(["chown", "-R", "10001:10001", config.WORK_REPO], check=False)
    tools = tools or ("Read,Glob,Grep,Edit,Write" if write else "Read,Glob,Grep")
    name = f"eva-sbx-{int(time.time())}"
    tmpdir = os.path.join(config.STATE_DIR, "tmp")
    fd, envfile = tempfile.mkstemp(prefix="eva-env-", dir=tmpdir if os.path.isdir(tmpdir) else None)
    try:
        with os.fdopen(fd, "w") as fh:
            for k, v in sandbox_env(key, config.ai_model(), config.EGRESS_PROXY).items():
                fh.write(f"{k}={v}\n")
        os.chmod(envfile, 0o600)  # lido só pelo docker (root); apagado ao fim
        cmd = build_cmd(name, envfile, prompt, system=system, schema=_loosen(schema) if schema else schema, request_dir=request_dir, write=write, tools=tools,
                        model=config.ai_model(), session_id=session_id)
        t0 = time.time()
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
            raise SandboxError("o agente excedeu o tempo limite") from None
    finally:
        try:
            os.remove(envfile)
        except OSError:
            pass
    out = (r.stdout or "").strip()
    try:
        data = json.loads(out.splitlines()[-1]) if out else {}
    except ValueError:
        data = {}
    if not data:
        raise SandboxError(f"resposta inválida do agente (código {r.returncode}): {(r.stderr or out)[-300:]}")
    res = {"structured": _coerce(data.get("structured_output"), schema) if schema and data.get("structured_output") is not None else data.get("structured_output"), "session_id": data.get("session_id") or session_id or "", "cost": data.get("total_cost_usd"),
           "is_error": bool(data.get("is_error")), "result": data.get("result", ""), "seconds": int(time.time() - t0)}
    if res["is_error"] or res["structured"] is None:
        import logging
        logging.getLogger("eva.sandbox").warning("agente sem saída estruturada: subtype=%s turns=%s result=%r stderr=%r",
                                                 data.get("subtype"), data.get("num_turns"), str(data.get("result", ""))[:500],
                                                 (r.stderr or "")[-800:])
        raise SandboxError(f"agente não concluiu ({data.get('subtype') or 'sem saída'}): {str(res['result'])[:300]}")
    return res


# O conversor de chamadas de ferramenta do provedor (MiMo via OpenRouter) quebra em campos com tipo união com null
# (ex.: ["integer", "null"]): o JSON sai truncado e a saída estruturada nunca fecha. Enviamos esses campos como texto e
# convertemos de volta aqui, conforme o esquema original.
def _loosen(schema):
    if isinstance(schema, dict):
        out = {}
        for k, v in schema.items():
            if k == "type" and isinstance(v, list) and "null" in v:
                base = [t for t in v if t != "null"]
                if base and base[0] in ("integer", "number", "boolean"):
                    out[k] = "string"
                    out["description"] = (schema.get("description", "") + " (texto; deixe vazio quando não se aplicar)").strip()
                    continue
                out[k] = base[0] if len(base) == 1 else base
                continue
            if k == "description" and "description" in out:
                continue
            out[k] = _loosen(v)
        return out
    if isinstance(schema, list):
        return [_loosen(x) for x in schema]
    return schema


def _coerce(value, schema):
    if not isinstance(schema, dict):
        return value
    t = schema.get("type")
    if isinstance(t, list) and "null" in t:
        base = next((x for x in t if x != "null"), None)
        if value is None or (isinstance(value, str) and value.strip().lower() in ("", "null", "none", "nenhum")):
            return None
        if base == "integer":
            try:
                return int(str(value).strip())
            except ValueError:
                return None
        if base == "number":
            try:
                return float(str(value).strip())
            except ValueError:
                return None
        if base == "boolean":
            return str(value).strip().lower() in ("true", "sim", "1", "yes")
    if isinstance(value, dict) and isinstance(schema.get("properties"), dict):
        return {k: _coerce(v, schema["properties"].get(k, {})) for k, v in value.items()}
    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        return [_coerce(v, schema["items"]) for v in value]
    return value
