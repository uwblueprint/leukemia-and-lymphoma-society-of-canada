from abc import ABC, abstractmethod

from app.schemas.email_template import EmailContent, EmailTemplateType


class IEmailServiceProvider(ABC):
    """
    Interface for Email Providers that interact with external
    email services (e.g., Amazon SES).
    """

    @abstractmethod
    def send_email(
        self, templateType: EmailTemplateType, content: EmailContent
    ) -> dict:
        """_summary_

        Args:
            templateType (EmailTemplate): Helps provider determine which
                template to use for the given email
            content (EmailContent): Contains the recipient and data to be
                used in the email

        Returns:
            dict: Provider-specific metadata if any
                (like message ID, thread ID, label IDs)
        """
        pass
