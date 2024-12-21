
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.schemas.schedule import ScheduleCreate, ScheduleInDB
from app.services.implementations.schedule_service import ScheduleService
from app.utilities.db_utils import get_db



router = APIRouter(
    prefix="/schedules",
    tags=["schedules"],
)


def get_schedule_service(db: Session = Depends(get_db)):
    return ScheduleService(db)

@router.post("/", response_model=ScheduleInDB)
async def create_schedule(
    schedule: ScheduleCreate, schedule_service: ScheduleService = Depends(get_schedule_service)
):
    try:
        created_schedule = await schedule_service.create_schedule(schedule)
        return created_schedule
    except HTTPException as http_ex:
        raise http_ex
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=str(e))

