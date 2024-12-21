import logging
from uuid import UUID
from datetime import datetime, timedelta

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import Schedule, TimeBlock
# from app.schemas.schedule import UserCreate, UserInDB, UserRole
# from app.schemas.time_block import UserCreate, UserInDB, UserRole
from app.interfaces.schedule_service import IScheduleService
from app.schemas.schedule import (
    ScheduleState,
    ScheduleCreate, 
    ScheduleInDB, 
    ScheduleAdd, 
    ScheduleData, 
    ScheduleRemove
)
from app.schemas.time_block import TimeBlockBase, TimeBlockId, TimeBlockFull, TimeBlockInDB

class ScheduleService(IScheduleService):
    def __init__(self, db: Session):
        self.db = db
        self.logger = logging.getLogger(__name__)

    def get_schedule_by_id(self, schedule_id):
        pass

    async def create_schedule(self, schedule: ScheduleCreate) -> ScheduleInDB:
        try:
            db_schedule = Schedule(
                scheduled_time=None,
                duration=None,
                state_id=ScheduleState.to_schedule_state_id("PENDING_VOLUNTEER_RESPONSE")
            )

            db_schedule.time_blocks = []

            # Add time blocks to the Schedule via the relationship
            for tb in schedule.time_blocks:
                db_schedule.time_blocks.append(TimeBlock(
                    start_time=tb.start_time,
                    end_time=tb.end_time
                ))
                

            # Add the Schedule object (and its time blocks) to the session
            # Time Blocks are inserted into db because of SqlAlchemy relationships
            self.db.add(db_schedule)
            self.db.commit()
            self.db.refresh(db_schedule)

            return ScheduleInDB.model_validate(db_schedule)
        except Exception as e:
            self.db.rollback()
            self.logger.error(f"Error creating Schedule: {str(e)}")
            raise HTTPException(status_code=500, detail=str(e))


    # CURRENTLY UNUSED
    async def create_time_block(self, schedule_id: int, time_block: TimeBlockBase) -> TimeBlockId:
        # takes a schedule id
        # create a time block in the db

        try:
            db_time_block = TimeBlock(
                schedule_id = schedule_id,
                start_time = time_block.start_time,
                end_time = time_block.end_time
            )


            self.db.add(db_time_block)
            self.db.commit()
            self.db.refresh(db_time_block)

            return TimeBlockId.model_validate(db_time_block)
        except Exception as e:
            self.db.rollback()
            self.logger.error(f"Error creating time block: {str(e)}")
            raise HTTPException(status_code=500, detail=str(e))


        # link the schedule + the time block together
        pass

    async def add_to_schedule(self, schedule: ScheduleAdd):
        pass
    
    async def remove_from_schedule(self, schedule: ScheduleRemove):

        # GET schedule
        # return schedule state, time_blocks
        #

        # click on the timeblock
        # PUT request {
            # timeBlockId: ...
        #}
        pass

    async def select_time(self, schedule_id: int, time: datetime):

        # loop through each time block associated with the schedule
        # check if time fits within a given timeblock (+1 hour)
        # 
        # if it does match, update the state of the schedule to SCHEDULED
        # if it doesn't match, then return an error
        pass
    
    async def complete_schedule(self, schedule_id: int):

        # update schedule state to COMPLETED
        pass

    async def get_schedule(self, schedule_id: int) -> ScheduleData:
        
        # returns a schedule
        pass


