"""Add verification_token to users

Revision ID: abe15985e8e6
Revises: f5de15ab97d2
Create Date: 2025-06-14 22:27:52.794051
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'abe15985e8e6'
down_revision: Union[str, None] = 'f5de15ab97d2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('users', sa.Column('verification_token', sa.String(), nullable=True))

def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('users', 'verification_token')
