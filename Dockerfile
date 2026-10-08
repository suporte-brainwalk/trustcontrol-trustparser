# Trust Parser — container da aplicação (web + worker)
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 TZ=America/Sao_Paulo
RUN apt-get update && apt-get install -y --no-install-recommends tini tzdata ca-certificates \
    && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --root-user-action=ignore -r requirements.txt

FROM base AS test
COPY requirements-dev.txt .
RUN pip install --root-user-action=ignore -r requirements-dev.txt
COPY . .

FROM base AS runtime
RUN useradd --system --uid 10001 --home /app parser
COPY --chown=parser:parser . .
USER parser
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=5 CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=4).status==200 else 1)"
ENTRYPOINT ["/usr/bin/tini", "--", "/app/deploy/entrypoint.sh"]
