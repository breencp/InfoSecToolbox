import os
import subprocess
from pathlib import Path
from dotenv import load_dotenv
import boto3
import json

# Load environment variables from .env file
load_dotenv()

# Environment variables
AWS_REGION = os.getenv("AWS_REGION")
SOURCE_DIR = os.getenv("SOURCE_DIR")
SES_EMAIL_ADDRESS = os.getenv("SES_EMAIL_ADDRESS")  # Verified email in SES
RECIPIENT_EMAIL = os.getenv("RECIPIENT_EMAIL")  # Recipient email

# AWS SES client
ses_client = boto3.client("ses", region_name=AWS_REGION)


def find_package_json_files(directory):
    """Find all package.json files in the given directory, skipping node_modules."""
    return [
        str(path)
        for path in Path(directory).rglob("package.json")
        if "node_modules" not in str(path) and "#current-cloud-backend" not in str(path)
    ]


def run_npm_audit(package_json_path):
    """Run npm audit in the directory of the package.json file."""
    package_dir = os.path.dirname(package_json_path)
    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=package_dir,
            capture_output=True,
            text=True,
        )
        if result.stdout:
            output = json.loads(result.stdout)
            if output.get('error', {}).get('code') == 'ENOLOCK':  # No lockfile found
                return {}
            else:
                return output
        else:
            return {}
    except Exception as e:
        print(f"Error running npm audit in {package_dir}: {e}")
        return {}


def summarize_severities(vulnerabilities):
    severities = {
        "critical": 0,
        "high": 0,
        "moderate": 0,
        "low": 0,
    }

    for _, v in vulnerabilities.items():
        severities[v["severity"]] += 1

    # remove 0 values
    severities = {k: v for k, v in severities.items() if v > 0}

    if len(severities.items()) == 0:
        return None

    # flatten json into single line string
    result = ', '.join([f"{k}: {v}" for k, v in severities.items()])
    return result


def generate_summary(results):
    """Generate a plain-text summary for the audit results."""
    summary_lines = []
    for package_name, highest_severity in results.items():
        summary_lines.append(f"{package_name}: {highest_severity}")
    return "\n".join(summary_lines)


def send_email(subject, body_text):
    ses_client.send_email(
        Source=SES_EMAIL_ADDRESS,
        Destination={"ToAddresses": [RECIPIENT_EMAIL]},
        Message={
            "Subject": {"Data": subject, "Charset": "UTF-8"},
            "Body": {
                "Text": {"Data": body_text, "Charset": "UTF-8"}
            },
        },
    )


def main():
    package_files = find_package_json_files(SOURCE_DIR)
    audit_results = {}

    for package_file in package_files:
        package_dir = os.path.dirname(package_file)
        package_name = package_dir.replace(f'{SOURCE_DIR}/', '')
        audit_output = run_npm_audit(package_file)

        if "error" in audit_output:
            try:
                audit_results[package_name] = audit_output["error"]["summary"]
            except:
                audit_results[package_name] = "Error"
        else:
            vulnerabilities = audit_output.get("vulnerabilities", {})
            result = summarize_severities(vulnerabilities)
            if result:
                audit_results[package_name] = summarize_severities(vulnerabilities)

    if audit_results:
        send_email("NPM Audit Summary", generate_summary(audit_results))


if __name__ == "__main__":
    main()
