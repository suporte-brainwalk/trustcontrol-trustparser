#!/usr/bin/env python3
"""Hook PreToolUse do agente (CLI) no sandbox da EVA: bloqueia leitura/escrita fora das áreas permitidas.

Recebe o evento em JSON no stdin. Saída com código 2 = ferramenta bloqueada (mensagem vai para o modelo).
"""
import json
import posixpath
import sys

sys.path.insert(0, "/opt/eva")
from paths import REPO_ROOT, can_read, can_write  # noqa: E402

READ_TOOLS = {"Read", "Glob", "Grep", "NotebookRead", "LS"}
WRITE_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
SAFE_TOOLS = {"StructuredOutput", "TodoWrite"}  # saída estruturada e lista de tarefas internas: não acessam arquivos nem rede


def deny(msg):
    print(f"Bloqueado pela política da EVA: {msg}", file=sys.stderr)
    sys.exit(2)


def main():
    try:
        ev = json.load(sys.stdin)
    except Exception:  # noqa: BLE001
        deny("evento inválido")
    tool = ev.get("tool_name", "")
    ti = ev.get("tool_input") or {}
    if tool in SAFE_TOOLS:
        sys.exit(0)
    if tool in READ_TOOLS:
        target = ti.get("file_path") or ti.get("path") or ti.get("notebook_path") or REPO_ROOT
        if not target.startswith("/"):
            target = posixpath.join(REPO_ROOT, target)
        ok, why = can_read(target)
        if not ok:
            deny(why)
        pat = ti.get("pattern") or ""
        if tool == "Glob" and (".." in pat or pat.startswith("/")) and not pat.startswith(REPO_ROOT):
            deny("padrão fora do repositório")
        sys.exit(0)
    if tool in WRITE_TOOLS:
        target = ti.get("file_path") or ti.get("notebook_path") or ""
        ok, why = can_write(target)
        if not ok:
            deny(f"{target}: {why}")
        sys.exit(0)
    deny(f"ferramenta não permitida: {tool}")


if __name__ == "__main__":
    main()
