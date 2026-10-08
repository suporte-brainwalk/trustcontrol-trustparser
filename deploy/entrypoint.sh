#!/bin/sh
# Aplica migrações, garante catálogo e sobe web (gunicorn) + worker supervisionados.
set -e
cd /app
alembic upgrade head
flask --app app:create_app seed >/dev/null || echo "seed falhou (continuando)"
exec supervisord -c /app/deploy/supervisord.conf
