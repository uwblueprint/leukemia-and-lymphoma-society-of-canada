from alembic import command
from alembic.config import Config

# Make sure all models are here to reflect all current models
# when autogenerating new migration
from .Base import Base
from .Role import Role
from .User import User
from .Schedule import Schedule
from .ScheduleState import ScheduleState
from .TimeBlock import TimeBlock

# Used to avoid import errors for the models
__all__ = ["Base", "User", "Role", "Schedule", "ScheduleState", "TimeBlock" ]


def run_migrations():
    alembic_cfg = Config("alembic.ini")
    # Emulates `alembic upgrade head` to migrate up to latest revision
    command.upgrade(alembic_cfg, "head")
