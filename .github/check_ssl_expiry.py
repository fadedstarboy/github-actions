import ssl
import socket
import datetime
import os
import requests
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Define a function to check SSL expiry
def check_ssl_expiry(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as sslsock:
                cert = sslsock.getpeercert(True)
                x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                expiry_date = x509_cert.not_valid_after

        days_remaining = (expiry_date - datetime.datetime.now()).days
        return days_remaining

    except Exception as e:
        return f"Error: {e}"

# Read the list of domains from a file (one domain per line)
domains_file = ".github/domains.txt"
if os.path.exists(domains_file):
    with open(domains_file, "r") as file:
        domains = file.read().splitlines()
else:
    domains = []

# Get Slack webhook URL from repository secrets
slack_webhook_url = os.environ["SLACK_WEBHOOK_URL"]

if not slack_webhook_url:
    print("Slack webhook URL not found in secrets.")
    exit(1)

# Check SSL expiry for each domain and send alert to Slack
for domain in domains:
    days_remaining = check_ssl_expiry(domain)
    if isinstance(days_remaining, int):
        message = (
            f"SSL Expiry Alert\n"
            f"  * Domain: {domain}\n"
            f"  * Warning: The SSL certificate for {domain} will expire in {days_remaining} days."
        )
    else:
        message = (
            f"SSL Expiry Alert\n"
            f"  * Domain: {domain}\n"
            f"  * Error: {days_remaining}"
        )

    payload = {
        "text": message
    }

    response = requests.post(slack_webhook_url, json=payload)
    if response.status_code != 200:
        print(f"Failed to send Slack notification for {domain}. Status code: {response.status_code}")


