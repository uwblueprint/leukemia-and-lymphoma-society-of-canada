"""insert schedule states

Revision ID: 991416bdc3f6
Revises: 40bc7d1cefc4
Create Date: 2024-11-22 18:21:24.174362

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '991416bdc3f6'
down_revision: Union[str, None] = '40bc7d1cefc4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.bulk_insert(
        sa.table(
            "schedule_states",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("name", sa.String(length=80), nullable=False),
        ),
        [
            {"id": 1, "name": "PENDING_VOLUNTEER_RESPONSE"},
            {"id": 2, "name": "PENDING_PARTICIPANT_RESPONSE"},
            {"id": 3, "name": "SCHEDULED"},
            {"id": 4, "name": "COMPLETED"}
        ],
    )
    


def downgrade() -> None:
    op.execute("DELETE FROM schedule_states WHERE id IN (1, 2, 3, 4)")
