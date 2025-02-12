import logging

from app.interfaces.email_service import IEmailService
from app.interfaces.email_service_provider import IEmailServiceProvider
from app.schemas.email_template import EmailContent, EmailData, EmailTemplateType


class EmailService(IEmailService):
    def __init__(self, provider: IEmailServiceProvider):
        self.provider = provider
        self.logger = logging.getLogger(__name__)

    def send_email(
        self, templateType: EmailTemplateType, content: EmailContent[EmailData]
    ) -> dict:
        self.logger.info(
            f"Sending email to {content.recipient} with template {templateType.value}"
        )
        return self.provider.send_email(templateType, content)
