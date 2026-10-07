from alembic import context

from app import models  # noqa: F401
from app.config import Settings
from app.database import Base, make_engine

config = context.config
settings = config.attributes.get("settings") or Settings()
if context.is_offline_mode():
    context.configure(
        url=settings.database_url,
        target_metadata=Base.metadata,
        literal_binds=True,
        version_table="vault_schema_version",
    )
    with context.begin_transaction():
        context.run_migrations()
else:
    engine = config.attributes.get("engine") or make_engine(settings.database_url)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata, version_table="vault_schema_version")
        with context.begin_transaction():
            context.run_migrations()
