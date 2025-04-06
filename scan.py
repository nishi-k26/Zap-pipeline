import time
import os
import requests
from zapv2 import ZAPv2
from dotenv import load_dotenv

load_dotenv()

# Retrieve sensitive information from environment variables
website_url = os.getenv('TARGET_URL')  # Use the environment variable for the URL
username = os.getenv('USERNAME')  # Use the environment variable for the username
password = os.getenv('PASSWORD')  # Use the environment variable for the password
api_key = os.getenv('API_KEY')  # Use the environment variable for the API key

# Retrieve scan settings from environment variables
attack_mode = os.getenv('ATTACK_MODE', 'false').lower() == 'true'  # Default to False if not set
scan_type = os.getenv('SCAN_TYPE', 'quick')  # Default to 'quick' if not set
max_depth = int(os.getenv('MAX_DEPTH', 5))  # Default to 5 if not set

# Check if the environment variables are set
if not website_url or not username or not password or not api_key:
    raise ValueError("Required environment variables (TARGET_URL, USERNAME, PASSWORD, API_KEY) are not set.")

# Start ZAP session with the API key
zap = ZAPv2(
    apikey=api_key,
    proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
)

# Open the target URL
print(f"Opening URL: {website_url}")
zap.urlopen(website_url)

# Handle authentication
print(f"Logging in as {username}...")
login_data = {
    'uid': username,
    'passw': password,
    'btnSubmit': 'Login'
}

# Send login request using requests library
response = requests.post(website_url, data=login_data)
if response.status_code == 200:
    print("Login successful")
else:
    print(f"Login failed with status code: {response.status_code}")
    exit(1)

# Configure the scan
if scan_type == "full":
    scan_policy = "Full Scan"
else:
    scan_policy = "Quick Scan"

# Start the spidering process
print(f"Spidering the website...")
zap.spider.scan(website_url)

# Wait for spidering to finish
while int(zap.spider.status()) < 100:
    print(f"Spidering: {zap.spider.status()}% complete")
    time.sleep(2)

# Configure and start active scanning
print(f"Starting {scan_policy}...")
scan_id = zap.ascan.scan(website_url)

# Configure scan settings
if attack_mode:
    zap.ascan.set_option_attack_policy(attack_mode)
zap.ascan.set_option_max_scans_in_ui(max_depth)

# Wait for the active scan to complete
while int(zap.ascan.status(scan_id)) < 100:
    print(f"Scan: {zap.ascan.status(scan_id)}% complete")
    time.sleep(2)

# Fetch and print alerts (vulnerabilities)
print("Scan completed. Fetching vulnerabilities...")
alerts = zap.core.alerts(baseurl=website_url)

# Save vulnerabilities to a file
print("Saving vulnerabilities to report.txt...")
with open("report.txt", "w") as report_file:
    report_file.write(f"Security Scan Report for {website_url}\n")
    report_file.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    report_file.write("-" * 80 + "\n\n")
    
    if not alerts:
        report_file.write("No vulnerabilities found.\n")
    else:
        for i, alert in enumerate(alerts, 1):
            report_file.write(f"Vulnerability #{i}\n")
            report_file.write(f"Risk Level: {alert.get('risk')}\n")
            report_file.write(f"Name: {alert.get('name')}\n")
            report_file.write(f"Description: {alert.get('description')}\n")
            report_file.write(f"Solution: {alert.get('solution')}\n")
            report_file.write("-" * 80 + "\n\n")

print("Report saved to report.txt")
