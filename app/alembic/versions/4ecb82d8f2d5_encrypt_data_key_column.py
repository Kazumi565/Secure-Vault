"""rename encryption_key to encrypted_data_key"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "4ecb82d8f2d5"
down_revision = "f5de15ab97d2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("files") as batch_op:
        batch_op.alter_column(
            "encryption_key",
            new_column_name="encrypted_data_key",
            existing_type=sa.String(),
            type_=sa.Text(),
            existing_nullable=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("files") as batch_op:
        batch_op.alter_column(
            "encrypted_data_key",
            new_column_name="encryption_key",
            existing_type=sa.Text(),
            type_=sa.String(),
            existing_nullable=False,
        )
