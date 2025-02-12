import json
import os
from typing import Dict

import boto3
from botocore.exceptions import ClientError

TEMPLATES_FILE = "app/utilities/ses/ses_templates.json"
TEMPLATES_DIR = "app/utilities/ses/template_files"

ses_client = boto3.client(
    "ses",
    region_name=os.getenv("AWS_REGION"),
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY"),
    aws_secret_access_key=os.getenv("AWS_SECRET_KEY"),
)


def load_templates_metadata(file_path: str) -> Dict:
    try:
        with open(file_path, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Error: {file_path} not found.")
        return []
    except json.JSONDecodeError as e:
        print(f"Error parsing {file_path}: {e}")
        return []


def load_file_content(file_path: str) -> str:
    """Reads the content of a file."""
    try:
        with open(file_path, "r") as file:
            return file.read()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return ""


# Function to create SES template
def create_ses_template(template_metadata):
    name = template_metadata["TemplateName"]
    try:
        text_part = load_file_content(template_metadata["TextPart"])
        html_part = load_file_content(template_metadata["HtmlPart"])
        if not text_part or not html_part:
            print(f"Skipping template '{name}' missing content.")
            return

        template = {
            "TemplateName": template_metadata["TemplateName"],
            "SubjectPart": template_metadata["SubjectPart"],
            "TextPart": text_part,
            "HtmlPart": html_part,
        }
        ses_client.create_template(Template=template)
        print(f"SES template '{name}' created successfully!")
    except ClientError as e:
        if e.response["Error"]["Code"] == "TemplateAlreadyExists":
            print(f"SES template '{name}' already exists.")
        else:
            print(f"An error occurred while creating the SES template: {e}")


# Ensure SES templates are available at app startup
def ensure_ses_templates():
    templates_metadata = load_templates_metadata(TEMPLATES_FILE)

    for template_metadata in templates_metadata:
        name = template_metadata["TemplateName"]
        try:
            # Check if the template exists
            ses_client.get_template(TemplateName=name)
            print(f"SES template '{name}' already exists.")
        except ClientError as e:
            if e.response["Error"]["Code"] == "TemplateDoesNotExist":
                print(f"SES template '{name}' does not exist. Creating template...")
                create_ses_template(template_metadata)
            else:
                print(f"An error occurred while checking the SES template: {e}")
