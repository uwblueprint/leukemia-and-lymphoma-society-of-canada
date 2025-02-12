import pytest
from botocore.exceptions import ClientError

from app.schemas.email_template import EmailContent, EmailTemplateType, MockEmailData
from app.services.email.amazon_ses_provider import AmazonSESEmailProvider

# Language: python


# Fake SES client to simulate boto3 SES client behavior.
class FakeSESClient:
    def list_verified_email_addresses(self):
        return {"VerifiedEmailAddresses": ["verified@example.com"]}

    def send_templated_email(self, **kwargs):
        return {"MessageId": "abc123"}

    def verify_email_identity(self, EmailAddress):
        # Simulate sending verification email
        print(f"Verification email sent to {EmailAddress}.")

    def get_template(self, TemplateName):
        # Simulate that template exists
        return True


@pytest.fixture
def fake_ses_client():
    return FakeSESClient()


@pytest.fixture
def provider(monkeypatch, fake_ses_client):
    # Patch boto3.client so that when AmazonSESEmailProvider is instantiated,
    # it uses our fake SES client.
    monkeypatch.setattr(
        "app.services.email.amazon_ses_provider.boto3.client",
        lambda service, **kwargs: fake_ses_client,
    )

    # Instantiate provider with sandbox mode enabled.
    provider = AmazonSESEmailProvider(
        aws_access_key="fake",
        aws_secret_key="fake",
        region="us-east-1",
        source_email="source@example.com",
        is_sandbox=True,
    )
    return provider


def test_send_email_success(provider):
    # Create dummy email content with a verified recipient.
    test_data = MockEmailData(name="User", date="2021-12-01")
    email_content = EmailContent[MockEmailData](
        recipient="verified@example.com", data=test_data
    )

    response = provider.send_email(EmailTemplateType.TEST, email_content)

    assert response["message"] == "Email sent successfully!"
    assert response["message_id"] == "abc123"


def test_send_email_failure(provider):
    # Simulate failure in send_templated_email by raising ClientError.
    def fake_send_templated_email(**kwargs):
        raise ClientError(
            {"Error": {"Message": "Failed to send email"}}, "send_templated_email"
        )

    provider.ses_client.send_templated_email = fake_send_templated_email

    test_data = MockEmailData(name="User", date="2021-12-01")
    email_content = EmailContent[MockEmailData](
        recipient="verified@example.com", data=test_data
    )

    response = provider.send_email(EmailTemplateType.TEST, email_content)
    assert "error" in response
    assert "Failed to send email" in response["error"]
