import uuid

from sqlalchemy import Column, DateTime, Enum, Interval, Integer, ForeignKey
from sqlalchemy.orm import relationship
from app.models.ScheduleState import ScheduleState

from .Base import Base


class Schedule(Base):
    __tablename__ = "schedules"

    id = Column(Integer, primary_key=True)
    scheduled_time = Column(DateTime, nullable = True)
    duration = Column(Interval, nullable = True)
    state_id = Column(Integer, ForeignKey("schedule_states.id"), nullable=False)

    state = relationship("ScheduleState")
    time_blocks = relationship("TimeBlock", back_populates="schedule")
