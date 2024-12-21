
from pydantic import BaseModel
from datetime import datetime
from uuid import UUID

class TimeBlockBase(BaseModel):
    start_time: datetime
    end_time: datetime

class TimeBlockId(BaseModel):
    id: UUID

class TimeBlockFull(TimeBlockBase, TimeBlockId):
    '''
    Combines TimeBlockBase and TimeBlockId.
    Represents a full time block with an ID and time range.
    '''
    pass

class TimeBlockInDB(BaseModel):
    id: UUID
    schedule_id: int
    start_time: datetime
    end_time: datetime
