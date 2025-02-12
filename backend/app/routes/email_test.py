from typing import Annotated

from fastapi import APIRouter, Depends

from app.interfaces.email_service import IEmailService
from app.schemas.email_template import EmailContent, EmailTemplateType, MockEmailData
from app.services.email.amazon_ses_provider import (
    get_email_service_provider,
)
from app.services.email.email_service import EmailService

router = APIRouter(
    prefix="/email",
    tags=["email"],
)


def get_email_service() -> IEmailService:
    return EmailService(provider=get_email_service_provider())


# TODO (Mayank, Nov 30th) - Remove test emails once email service is fully implemented
@router.post("/send-test")
async def send_welcome_email(
    recipient: str,
    user_name: str,
    email_service: Annotated[IEmailService, Depends(get_email_service)],
):
    return email_service.send_email(
        templateType=EmailTemplateType.TEST,
        content=EmailContent[MockEmailData](
            recipient=recipient, data=MockEmailData(name=user_name, date="2021-12-01")
        ),
    )
