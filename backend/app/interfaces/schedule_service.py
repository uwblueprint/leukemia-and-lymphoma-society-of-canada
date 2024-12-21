from abc import ABC, abstractmethod
from app.schemas.schedule import ScheduleCreate, ScheduleInDB, ScheduleAdd, ScheduleData, ScheduleRemove

class IScheduleService(ABC):
    """
    ScheduleService interface
    """

    @abstractmethod
    def get_schedule_by_id(self, schedule_id):
        """
        Get schedule associated with schedule_id

        :param schedule_id: schedule's id
        :type schedule: str
        :return: a ScheduleDTO with schedule's information
        :rtype: ScheduleDTO
        :raises Exception: if schedule retrieval fails
        """
        pass

    @abstractmethod
    def create_schedule(self, schedule: ScheduleCreate) -> ScheduleInDB:
        pass


    # create schedule

    # update schedule status

    # delete schedule

    # add timeblock
    # edit timeblock
    # remove timeblock


