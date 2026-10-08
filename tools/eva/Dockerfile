# Orquestrador da EVA: código determinístico (caixa de e-mail, política, testes, verificação visual, deploy, rollback).
# O agente NÃO roda aqui: roda em container sandbox separado (Dockerfile.sandbox), sem segredos e com rede só para openrouter.ai.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 TZ=America/Sao_Paulo PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN apt-get update && apt-get install -y --no-install-recommends git openssh-client ca-certificates tini tzdata \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /opt/eva/requirements.txt
RUN pip install --root-user-action=ignore -r /opt/eva/requirements.txt && playwright install --with-deps chromium && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/eva
COPY orchestrator /opt/eva/orchestrator
COPY sandbox /opt/eva/sandbox
COPY tests /opt/eva/tests
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "orchestrator.main"]
