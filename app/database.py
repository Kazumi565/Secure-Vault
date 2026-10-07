from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker


class Base(DeclarativeBase):
    pass


def make_engine(url):
    kwargs = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def configure_sqlite(connection, _):
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=30000")

    return engine


def session_factory(engine):
    return sessionmaker(engine, expire_on_commit=False)
