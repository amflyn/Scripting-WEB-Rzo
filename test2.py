import requests
import socket
import ssl
import dns.resolver
import urllib.parse
import json
from bs4 import BeautifulSoup


def get_certificate_info(domain):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
    conn.connect((domain, 443))
    cert = conn.getpeercert()

    print("\nCertificate Information:")
    for key, value in cert.items():
        print(f"{key}: {value}")

    # Display chain of trust
    cert_chain = conn.getpeercert(True)
    chain_pem = ssl.DER_cert_to_PEM_cert(cert_chain)
    print("\nCertificate Chain of Trust:")
    print(chain_pem)

# The website to query
website_url = "https://taisen.fr"

# Resolve the DNS
parsed_url = urllib.parse.urlparse(website_url)
hostname = parsed_url.hostname
resolver = dns.resolver.Resolver()
answers = resolver.resolve(hostname, 'A')
dns_ip = answers[0].address
print(f"DNS resolved IP: {dns_ip}")

# Get the name of the DNS server
dns_servers = resolver.nameservers
print(f"DNS servers: {dns_servers}")

# Establish connection and fetch data
response = requests.get(website_url)

# Local machine IP and port
local_ip = socket.gethostbyname(socket.gethostname())

# Create a temporary socket to determine the local port
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.connect(("8.8.8.8", 80))
    local_port = s.getsockname()[1]

print(f"Source IP: {local_ip}")
print(f"Source Port: {local_port}")

# Destination IP and port
destination_ip = socket.gethostbyname(hostname)
destination_port = 443 if parsed_url.scheme == "https" else 80

print(f"Destination IP: {destination_ip}")
print(f"Destination Port: {destination_port}")

# Headers
print("\nHeaders:")
for header, value in response.headers.items():
    print(f"{header}: {value}")
    # Explain some common headers
    if header.lower() == "content-type":
        print("Content-Type header indicates the media type of the resource.")
    elif header.lower() == "server":
        print("Server header contains information about the software used by the origin server.")
    elif header.lower() == "date":
        print("Date header represents the date and time at which the message was originated.")

# Content-Type
content_type = response.headers.get('Content-Type', 'unknown')
print(f"\nContent-Type: {content_type}")
if 'text/html' in content_type:
    print("This indicates that the response content is HTML.")
elif 'application/json' in content_type:
    print("This indicates that the response content is JSON data.")

# Parse HTML and store tags in an array
soup = BeautifulSoup(response.content, 'html.parser')
tags = [tag.name for tag in soup.find_all()]
print("\nHTML Tags found on the page:")
print(tags)

domain= website_url.replace("https://","").replace("http://","")
get_certificate_info(domain)


# Traceroute (requires elevated permissions)
import subprocess
print("\nTraceroute:")
result = subprocess.run(["tracert", hostname], capture_output=True, text=True)  # Use tracert for Windows
print(result.stdout)
