"""add schedule, schedule_state, and time_block models

Revision ID: 40bc7d1cefc4
Revises: c9bc2b4d1036
Create Date: 2024-11-22 18:08:50.027085

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '40bc7d1cefc4'
down_revision: Union[str, None] = 'c9bc2b4d1036'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('schedule_states',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=80), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('schedules',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('scheduled_time', sa.DateTime(), nullable=True),
    sa.Column('duration', sa.Interval(), nullable=True),
    sa.Column('state_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['state_id'], ['schedule_states.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('time_blocks',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('schedule_id', sa.Integer(), nullable=False),
    sa.Column('start_time', sa.DateTime(), nullable=True),
    sa.Column('end_time', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['schedule_id'], ['schedules.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('time_blocks')
    op.drop_table('schedules')
    op.drop_table('schedule_states')
    # ### end Alembic commands ###
