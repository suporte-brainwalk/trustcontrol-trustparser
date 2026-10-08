"""Configuração do orquestrador da EVA (caminhos idênticos no host e no container — necessário para montar volumes via Docker)."""
import os

MAILBOX = os.getenv("EVA_MAILBOX", "eva-trustparser@trustcontrol.nuvem.tec.br")
FROM_NAME = "EVA · Suporte e Manutenção por IA · Trust Parser"
SIGNATURE = "EVA · Suporte e Manutenção por IA · Trust Parser"
IMAP_HOST = os.getenv("EVA_IMAP_HOST", "postfix-mail")
SMTP_HOST = os.getenv("EVA_SMTP_HOST", "postfix-mail")
SMTP_PORT = int(os.getenv("EVA_SMTP_PORT", "25"))
MAIL_PASSWORD = os.getenv("EVA_MAIL_PASSWORD", "")
DATABASE_URL = os.getenv("DATABASE_URL", "")
PORTAL_URL = os.getenv("EVA_PORTAL_URL", "https://trustparser.trustcontrol.nuvem.tec.br")

STATE_DIR = os.getenv("EVA_STATE_DIR", "/srv/eva")
WORK_REPO = os.path.join(STATE_DIR, "work", "repo")
REQUESTS_DIR = os.path.join(STATE_DIR, "requests")
SANDBOX_HOME = os.path.join(STATE_DIR, "sandbox-home")
APP_DIR = os.getenv("EVA_APP_DIR", "/root/trustcontrol-trustparser/tools/eva")

PROD_REPO = os.getenv("EVA_PROD_REPO", "/root/trustcontrol-trustparser")
GIT_REMOTE = os.getenv("EVA_GIT_REMOTE", "git@github-tc-trustparser:suporte-brainwalk/trustcontrol-trustparser.git")
GIT_BRANCH = os.getenv("EVA_GIT_BRANCH", "main")
COMPOSE_FILE = os.getenv("EVA_COMPOSE_FILE", "/root/docker-compose.yml")
# serviços do compose publicados a partir do repositório (mesma imagem): web+worker e receptor syslog
APP_SERVICE = os.getenv("EVA_APP_SERVICE", "parser-app")
INGEST_SERVICE = os.getenv("EVA_INGEST_SERVICE", "parser-ingest")
APP_SERVICES = [s for s in (APP_SERVICE, INGEST_SERVICE) if s]
APP_IMAGE = os.getenv("EVA_APP_IMAGE", "trustparser-app")
APP_ENV_FILE = os.getenv("EVA_APP_ENV", "/root/trustparser/secrets/app.env")
SECRET_ENV_FILES = [APP_ENV_FILE, "/root/trustparser/secrets/postgres.env", "/root/trustparser/secrets/openrouter.env",
                    "/root/trustparser/secrets/eva.env", "/root/trustparser/secrets/eva-mail.env"]
DOCKER_NETWORK = os.getenv("EVA_DOCKER_NETWORK", "trustparser_net")
NGINX_HOST = os.getenv("EVA_NGINX_HOST", "nginx-proxy")
# a verificação no ar exige batimento do worker (healthz.worker_heartbeat_age_s < 120 s)
REQUIRE_WORKER_HEARTBEAT = os.getenv("EVA_REQUIRE_WORKER_HEARTBEAT", "1") == "1"

# ---- IA: harness Claude Code (CLI) dentro do sandbox, apontado para o endpoint compatível do OpenRouter.
# Nunca citar fabricante/modelo em respostas (policy.AI_VENDOR_NAMES).
CLAUDE_BIN = os.getenv("EVA_CLAUDE_BIN", "/root/.local/bin/claude")
OPENROUTER_ENV_FILE = os.getenv("EVA_OPENROUTER_ENV", "/root/trustparser/secrets/openrouter.env")
OPENROUTER_BASE = os.getenv("EVA_OPENROUTER_BASE", "https://openrouter.ai/api")  # Anthropic-compatível (/v1/messages)
OPENROUTER_API = os.getenv("EVA_OPENROUTER_API", "https://openrouter.ai/api/v1")  # chat completions e /key
AI_MODEL_DEFAULT = "xiaomi/mimo-v2.6-pro"
AI_KEY_MIN_USD = float(os.getenv("EVA_AI_KEY_MIN_USD", "0.30"))  # aviso quando o saldo do limite da chave fica abaixo disto

# avisos operacionais da EVA (parada, IA, caixa, disco...): não inclui as cópias das conversas
ALERT_TO = os.getenv("EVA_ALERT_TO", "suporte.trustcontrol@brainwalk.com.br")
# leitura de dados do Trust Parser pela API v1 (chave protegida da EVA; o agente nunca a vê)
API_BASE = os.getenv("EVA_API_BASE", "http://parser-app:8000/api/v1")
API_KEY = os.getenv("EVA_API_KEY", "")
SANDBOX_IMAGE = os.getenv("EVA_SANDBOX_IMAGE", "eva-sandbox:latest")
SANDBOX_NETWORK = os.getenv("EVA_SANDBOX_NETWORK", "eva_sandbox")
EGRESS_PROXY = os.getenv("EVA_EGRESS_PROXY", "http://eva-egress:3128")

POLL_SECONDS = int(os.getenv("EVA_POLL_SECONDS", "60"))
DRY_RUN_DEPLOY = os.getenv("EVA_DRY_RUN_DEPLOY", "0") == "1"  # testes: não publica nem faz push
TEST_DB = os.getenv("EVA_TEST_DB", "trustparser_eva_test")
MAINT_CONTAINER = os.getenv("EVA_MAINT_CONTAINER", "parser-app")  # onde a manutenção é executada (app.services.eva_maintenance)
OUTBOUND_REDIRECT = os.getenv("EVA_OUTBOUND_REDIRECT", "")  # testes: toda resposta vai para este endereço (destinatários reais em cabeçalho)
DEMO_EXTRA_SENDERS = {e.strip().lower() for e in os.getenv("EVA_DEMO_EXTRA_SENDERS", "").split(",") if e.strip()}


def _read_env(path: str) -> dict:
    out = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


def openrouter_key() -> str:
    """Chave dedicada da EVA (OPENROUTER_API_KEY no ambiente ou no arquivo de segredos). Relida a cada uso: rotação sem reinício."""
    return os.getenv("OPENROUTER_API_KEY") or _read_env(OPENROUTER_ENV_FILE).get("OPENROUTER_API_KEY", "")


def ai_model() -> str:
    return os.getenv("OPENROUTER_MODEL") or _read_env(OPENROUTER_ENV_FILE).get("OPENROUTER_MODEL", "") or AI_MODEL_DEFAULT
