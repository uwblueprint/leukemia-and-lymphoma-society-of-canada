import json
from abc import ABC
from dataclasses import dataclass
from enum import Enum
from typing import Generic, TypeVar

EmailData = TypeVar("EmailData")


class TemplateData(ABC):
    def get_formatted_string(self) -> str:
        class_dict = self.__dict__
        try:
            formatted_string = json.dumps(class_dict)  # Try to convert to a JSON string
        except (TypeError, ValueError) as e:
            raise Exception(f"Error converting class to JSON: {e}")

        return formatted_string


@dataclass
class MockEmailData(TemplateData):
    name: str
    date: str


class EmailTemplateType(Enum):
    TEST = "Test"


@dataclass
class EmailContent(Generic[EmailData]):
    recipient: str
    data: EmailData
