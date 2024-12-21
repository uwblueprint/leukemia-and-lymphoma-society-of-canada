from sqlalchemy import Column, Integer, String

from .Base import Base


class ScheduleState(Base):
    __tablename__ = "schedule_states"
    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
