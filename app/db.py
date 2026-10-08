"""Engine e sessão SQLAlchemy (sem Flask-SQLAlchemy, para ser usado igual na web e no worker)."""
from contextlib import contextmanager
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, scoped_session, sessionmaker

engine = None
Session = scoped_session(sessionmaker(expire_on_commit=False, future=True))


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def init_engine(url: str, **kw):
    global engine
    if not url:
        raise RuntimeError("DATABASE_URL não configurada")
    engine = create_engine(url, pool_pre_ping=True, pool_size=kw.get("pool_size", 5),
                           max_overflow=kw.get("max_overflow", 5), future=True)
    Session.configure(bind=engine)
    return engine


@contextmanager
def session_scope():
    """Transação curta para o worker: commit no fim, rollback em erro."""
    s = Session()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        Session.remove()
