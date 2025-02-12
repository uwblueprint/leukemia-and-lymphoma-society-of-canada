from abc import ABC, abstractmethod

from app.schemas.email_template import EmailContent, EmailTemplateType


class IEmailService(ABC):
    """
    Interface for the Email Service, defining the core email operations such as
    sending templated and custom emails.
    """

    @abstractmethod
    def send_email(
        self, templateType: EmailTemplateType, content: EmailContent
    ) -> dict:
        """Send an email using the given template and content with a
            respective service provider.

        Args:
            templateType (EmailTemplateType): Specifies the template
                to be used for the email
            content (EmailContent): Contains the recipient and data
                to be used in the email

        Returns:
            dict: Provider-specific metadata if any
                (like message ID, thread ID, label IDs)
        """
        pass
