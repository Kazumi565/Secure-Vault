"""Create vault v2 schema
Revision: 20261007_01
"""

import sqlalchemy as sa
from alembic import op

revision = "20261007_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "accounts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("hashed_password", sa.Text(), nullable=False),
        sa.Column("full_name", sa.String(length=120), nullable=False),
        sa.Column("role", sa.String(length=12), nullable=False),
        sa.Column("verified", sa.Boolean(), nullable=False),
        sa.Column("used_bytes", sa.BigInteger(), nullable=False),
        sa.Column("avatar_key", sa.String(length=200), nullable=True),
        sa.Column("totp_secret", sa.Text(), nullable=True),
        sa.Column("pending_totp", sa.Text(), nullable=True),
        sa.Column("pending_totp_at", sa.DateTime(), nullable=True),
        sa.Column("last_totp_step", sa.Integer(), nullable=False),
        sa.Column("recovery_codes", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sqlite_autoincrement=True,
    )
    op.create_index(op.f("ix_accounts_email"), "accounts", ["email"], unique=True)
    op.create_table(
        "mail_outbox",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("encrypted_payload", sa.Text(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("available_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "rate_buckets",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )
    op.create_index(op.f("ix_rate_buckets_expires_at"), "rate_buckets", ["expires_at"], unique=False)
    op.create_table(
        "storage_garbage",
        sa.Column("key", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )
    op.create_table(
        "action_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("purpose", sa.String(length=16), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(op.f("ix_action_tokens_user_id"), "action_tokens", ["user_id"], unique=False)
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("actor_id", sa.Integer(), nullable=True),
        sa.Column("owner_id", sa.Integer(), nullable=True),
        sa.Column("actor_email", sa.String(length=254), nullable=False),
        sa.Column("file_id", sa.Integer(), nullable=True),
        sa.Column("filename", sa.String(length=240), nullable=True),
        sa.Column("action", sa.String(length=60), nullable=False),
        sa.Column("detail", sa.String(length=500), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["actor_id"], ["accounts.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["owner_id"], ["accounts.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_audit_events_action"), "audit_events", ["action"], unique=False)
    op.create_index(op.f("ix_audit_events_actor_id"), "audit_events", ["actor_id"], unique=False)
    op.create_index(op.f("ix_audit_events_created_at"), "audit_events", ["created_at"], unique=False)
    op.create_index(op.f("ix_audit_events_owner_id"), "audit_events", ["owner_id"], unique=False)
    op.create_table(
        "login_sessions",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("csrf", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("agent", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(op.f("ix_login_sessions_user_id"), "login_sessions", ["user_id"], unique=False)
    op.create_table(
        "vault_folders",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("owner_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.ForeignKeyConstraint(["owner_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("owner_id", "name"),
    )
    op.create_index(op.f("ix_vault_folders_owner_id"), "vault_folders", ["owner_id"], unique=False)
    op.create_table(
        "vault_files",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("owner_id", sa.Integer(), nullable=False),
        sa.Column("folder_id", sa.Integer(), nullable=True),
        sa.Column("filename", sa.String(length=240), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("current_version", sa.Integer(), nullable=False),
        sa.Column("version_counter", sa.Integer(), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("mime_type", sa.String(length=100), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["folder_id"], ["vault_folders.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["owner_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sqlite_autoincrement=True,
    )
    op.create_index(op.f("ix_vault_files_deleted_at"), "vault_files", ["deleted_at"], unique=False)
    op.create_index(
        "ix_vault_files_owner_deleted_updated", "vault_files", ["owner_id", "deleted_at", "updated_at"], unique=False
    )
    op.create_index(op.f("ix_vault_files_owner_id"), "vault_files", ["owner_id"], unique=False)
    op.create_table(
        "file_versions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("file_id", sa.Integer(), nullable=False),
        sa.Column("number", sa.Integer(), nullable=False),
        sa.Column("storage_key", sa.String(length=200), nullable=False),
        sa.Column("wrapped_key", sa.Text(), nullable=False),
        sa.Column("format", sa.String(length=12), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["file_id"], ["vault_files.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("file_id", "number"),
        sa.UniqueConstraint("storage_key"),
    )
    op.create_index(op.f("ix_file_versions_file_id"), "file_versions", ["file_id"], unique=False)
    op.create_table(
        "share_links",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("file_id", sa.Integer(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("downloads", sa.Integer(), nullable=False),
        sa.Column("max_downloads", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["file_id"], ["vault_files.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(op.f("ix_share_links_file_id"), "share_links", ["file_id"], unique=False)


def downgrade():
    op.drop_index(op.f("ix_share_links_file_id"), table_name="share_links")
    op.drop_table("share_links")
    op.drop_index(op.f("ix_file_versions_file_id"), table_name="file_versions")
    op.drop_table("file_versions")
    op.drop_index(op.f("ix_vault_files_owner_id"), table_name="vault_files")
    op.drop_index("ix_vault_files_owner_deleted_updated", table_name="vault_files")
    op.drop_index(op.f("ix_vault_files_deleted_at"), table_name="vault_files")
    op.drop_table("vault_files")
    op.drop_index(op.f("ix_vault_folders_owner_id"), table_name="vault_folders")
    op.drop_table("vault_folders")
    op.drop_index(op.f("ix_login_sessions_user_id"), table_name="login_sessions")
    op.drop_table("login_sessions")
    op.drop_index(op.f("ix_audit_events_owner_id"), table_name="audit_events")
    op.drop_index(op.f("ix_audit_events_created_at"), table_name="audit_events")
    op.drop_index(op.f("ix_audit_events_actor_id"), table_name="audit_events")
    op.drop_index(op.f("ix_audit_events_action"), table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_index(op.f("ix_action_tokens_user_id"), table_name="action_tokens")
    op.drop_table("action_tokens")
    op.drop_table("storage_garbage")
    op.drop_index(op.f("ix_rate_buckets_expires_at"), table_name="rate_buckets")
    op.drop_table("rate_buckets")
    op.drop_table("mail_outbox")
    op.drop_index(op.f("ix_accounts_email"), table_name="accounts")
    op.drop_table("accounts")
