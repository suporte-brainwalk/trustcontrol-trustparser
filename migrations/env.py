import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine

from app.db import Base
from app import models  # noqa: F401  (registra as tabelas)

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)
target_metadata = Base.metadata


def run_migrations_online():
    engine = create_engine(os.environ["DATABASE_URL"])
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
