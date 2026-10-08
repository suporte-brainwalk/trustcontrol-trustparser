"""EVA: valores padrão no banco para colunas obrigatórias (o orquestrador insere sem passar por modelos ORM).

Revision ID: b1e2c3d4f5a6
Revises: 4fd31e980d77
"""
from alembic import op

revision = "b1e2c3d4f5a6"
down_revision = "4fd31e980d77"
branch_labels = None
depends_on = None

DEFAULTS = {
    "eva_threads": {"session_id": "''", "state": "'em_andamento'", "message_ids": "'[]'::jsonb", "pending": "'[]'::jsonb",
                    "reminders_sent": "0", "created_at": "now()", "updated_at": "now()", "subject": "''"},
    "eva_requests": {"subject": "''", "received_at": "now()", "status": "'queued'", "intent": "''", "summary": "''", "commit_sha": "''",
                     "deployed": "false", "rolled_back": "false", "error": "''", "reply_message_id": "''", "details": "'{}'::jsonb"},
    "eva_messages": {"subject": "''", "body_text": "''", "body_html": "''", "reply": "'{}'::jsonb", "status_key": "''", "status_text": "''",
                     "emailed": "false", "created_at": "now()"},
    "eva_whitelist": {"name": "''", "active": "true", "added_by": "''", "added_at": "now()"},
    "eva_attachments": {"created_at": "now()"},
}


def upgrade():
    for table, cols in DEFAULTS.items():
        for col, val in cols.items():
            op.execute(f"alter table {table} alter column {col} set default {val}")


def downgrade():
    for table, cols in DEFAULTS.items():
        for col in cols:
            op.execute(f"alter table {table} alter column {col} drop default")
