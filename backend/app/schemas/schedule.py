from enum import Enum
from uuid import UUID
from datetime import datetime, timedelta
from typing import List, Optional
from app.schemas.time_block import TimeBlockBase, TimeBlockId, TimeBlockFull
from pydantic import BaseModel, ConfigDict



class ScheduleState(str, Enum):
    PENDING_PARTICIPANT = "PENDING_PARTICIPANT_RESPONSE"
    PENDING_VOLUNTEER = "PENDING_VOLUNTEER_RESPONSE"
    SCHEDULED = "SCHEDULED"
    COMPLETED = "COMPLETED"

    @classmethod
    def to_schedule_state_id(cls, state: "ScheduleState") -> int:
        state_map = {
            cls.PENDING_VOLUNTEER: 1,
            cls.PENDING_PARTICIPANT: 2,
            cls.SCHEDULED: 3,
            cls.COMPLETED: 4}

        return state_map[state]

class ScheduleBase(BaseModel):
    scheduled_time: Optional[datetime]
    duration: Optional[timedelta]
    state_id: int


class ScheduleInDB(ScheduleBase):
    id: int

    model_config = ConfigDict(from_attributes=True)

# Provides both Schedule data and full TimeBlock data 
class ScheduleData(ScheduleInDB):
    time_blocks: List[TimeBlockFull]

# List of Start and End times to Create a Schedule with
class ScheduleCreate(BaseModel):
    time_blocks: List[TimeBlockBase]

class ScheduleAdd(BaseModel):
    schedule_id: UUID
    time_blocks: List[TimeBlockBase]

class ScheduleRemove(BaseModel):
    schedule_id: UUID
    time_blocks: List[TimeBlockId]

