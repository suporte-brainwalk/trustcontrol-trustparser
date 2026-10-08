"""Git: cópia de trabalho da EVA, commit, push, revert e atualização do repositório de produção."""
from __future__ import annotations

import os
import re
import subprocess

from . import config

GIT_ENV = {**os.environ, "GIT_SSH_COMMAND": "ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new", "GIT_TERMINAL_PROMPT": "0"}
AUTHOR = ("EVA", "eva-trustparser@trustcontrol.nuvem.tec.br")


SIM_BRANCH = "eva-simulado"


class GitError(RuntimeError):
    pass


def git(*args, cwd=None, check=True, timeout=300) -> str:
    r = subprocess.run(["git", "-c", "safe.directory=*", *args], cwd=cwd or config.WORK_REPO, env=GIT_ENV, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise GitError(f"git {' '.join(args[:2])}: {(r.stderr or r.stdout).strip()[-400:]}")
    return r.stdout.strip()


def sync_worktree() -> str:
    """Cópia limpa e idêntica ao GitHub (origin/main). Retorna o SHA base."""
    if not os.path.isdir(os.path.join(config.WORK_REPO, ".git")):
        os.makedirs(os.path.dirname(config.WORK_REPO), exist_ok=True)
        git("clone", "--branch", config.GIT_BRANCH, config.GIT_REMOTE, config.WORK_REPO, cwd=os.path.dirname(config.WORK_REPO), timeout=600)
    git("fetch", "origin", config.GIT_BRANCH, timeout=300)
    target = f"origin/{config.GIT_BRANCH}"
    if config.DRY_RUN_DEPLOY and git("branch", "--list", SIM_BRANCH):
        target = SIM_BRANCH  # modo simulado: o "GitHub" é um branch local, para desfazer funcionar como em produção
    git("reset", "--hard", target)
    git("clean", "-fdx")
    return git("rev-parse", "HEAD")


def staged_patch() -> str:
    git("add", "-A")
    return git("diff", "--cached", "--binary", "--no-color", "--find-renames")


def changed_files() -> list[str]:
    git("add", "-A")
    out = git("diff", "--cached", "--name-only")
    return [x for x in out.splitlines() if x]


def reset_worktree():
    git("reset", "--hard")
    git("clean", "-fdx")


def commit(message: str) -> str:
    git("add", "-A")
    git("-c", f"user.name={AUTHOR[0]}", "-c", f"user.email={AUTHOR[1]}", "commit", "-q", "-m", message)
    return git("rev-parse", "HEAD")


def push() -> None:
    """Push para main; se o GitHub andou, faz rebase (sem conflito) e tenta de novo."""
    if config.DRY_RUN_DEPLOY:
        git("branch", "-f", SIM_BRANCH, "HEAD")
        return
    for _ in range(3):
        r = subprocess.run(["git", "-c", "safe.directory=*", "push", "origin", f"HEAD:{config.GIT_BRANCH}"], cwd=config.WORK_REPO, env=GIT_ENV,
                           capture_output=True, text=True, timeout=300)
        if r.returncode == 0:
            return
        git("fetch", "origin", config.GIT_BRANCH)
        rb = subprocess.run(["git", "-c", "safe.directory=*", "rebase", f"origin/{config.GIT_BRANCH}"], cwd=config.WORK_REPO, env=GIT_ENV,
                            capture_output=True, text=True)
        if rb.returncode != 0:
            git("rebase", "--abort", check=False)
            raise GitError("o repositório mudou ao mesmo tempo e há conflito com esta alteração")
    raise GitError("não foi possível enviar ao GitHub")


def revert(sha: str) -> str:
    r = subprocess.run(["git", "-c", "safe.directory=*", "-c", f"user.name={AUTHOR[0]}", "-c", f"user.email={AUTHOR[1]}", "revert", "--no-edit", sha],
                       cwd=config.WORK_REPO, env=GIT_ENV, capture_output=True, text=True)
    if r.returncode != 0:
        git("revert", "--abort", check=False)
        if re.search(r"(?i)bad revision|unknown revision|bad object", r.stderr or ""):
            raise GitError("não encontrei essa versão no histórico")
        raise GitError("conflito ao desfazer (há mudanças posteriores na mesma parte)")
    return git("rev-parse", "HEAD")


def prod_status() -> tuple[bool, str]:
    """Produção pode receber pull? (sem arquivos rastreados modificados)."""
    if config.DRY_RUN_DEPLOY:
        return True, "simulado"
    dirty = git("status", "--porcelain", "--untracked-files=no", cwd=config.PROD_REPO)
    if dirty:
        return False, "há alterações locais não publicadas no servidor"
    return True, git("rev-parse", "HEAD", cwd=config.PROD_REPO)


def prod_pull() -> str:
    if config.DRY_RUN_DEPLOY:
        return git("rev-parse", "HEAD", cwd=config.PROD_REPO)
    git("fetch", "origin", config.GIT_BRANCH, cwd=config.PROD_REPO)
    git("merge", "--ff-only", f"origin/{config.GIT_BRANCH}", cwd=config.PROD_REPO)
    return git("rev-parse", "HEAD", cwd=config.PROD_REPO)
