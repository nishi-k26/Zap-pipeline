import time
import os
import requests
from zapv2 import ZAPv2
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

load_dotenv()

# Retrieve sensitive information from environment variables
website_url = os.getenv('TARGET_URL')
username = os.getenv('USERNAME')
password = os.getenv('PASSWORD')
api_key = os.getenv('API_KEY')

# Retrieve scan settings from environment variables
attack_mode = os.getenv('ATTACK_MODE', 'false').lower() == 'true'
scan_type = os.getenv('SCAN_TYPE', 'quick')
max_depth = int(os.getenv('MAX_DEPTH', 5))
zap_address = "http://127.0.0.1:8080"

# Check if the environment variables are set
if not website_url or not username or not password or not api_key:
    raise ValueError("Required environment variables (TARGET_URL, USERNAME, PASSWORD, API_KEY) are not set.")

# Function to check if ZAP is ready
def check_zap_ready(zap_address):
    try:
        response = requests.get(f"{zap_address}/")
        return response.status_code == 200
    except requests.exceptions.RequestException as e:
        print(f"Error checking ZAP status: {e}")
        return False

# Check if ZAP is ready
if not check_zap_ready(zap_address):
    print("ZAP instance is not ready. Exiting.")
    exit(1)

# Start ZAP session with the API key
print(f"Using proxy: {zap_address}")
print(f"Using API key: {api_key}")

session = requests.Session()
retry = Retry(connect=10, backoff_factor=1.0)
adapter = HTTPAdapter(max_retries=retry, pool_connections=1, pool_maxsize=1)
session.mount('http://', adapter)
session.mount('https://', adapter)

# Remove the 'session' argument from the ZAPv2 constructor
zap = ZAPv2(apikey=api_key, proxies={'http': zap_address, 'https': zap_address})

# Open the target URL
try:
    print(f"Opening URL: {website_url}")
    zap.urlopen(website_url)
except Exception as e:
    print(f"Error opening URL: {e}")
    exit(1)

# Handle authentication
print(f"Logging in as {username}...")
login_data = {
    'uid': username,
    'passw': password,
    'btnSubmit': 'Login'
}

# Send login request using requests library
response = requests.post(website_url, data=login_data)
# print(f"Login response: {response.text}")
if response.status_code == 200:
    print("Login successful")
else:
    print(f"Login failed with status code: {response.status_code}")
    exit(1)

# Add delay before spidering
print("Waiting for ZAP to be ready...")
time.sleep(30)  # Increase sleep time if necessary

# Start the spidering process
try:
    print(f"Spidering the website: {website_url}")
    zap.spider.scan(website_url)
except Exception as e:
    print(f"Error during spidering: {e}")
    exit(1)

# Wait for spidering to finish
while int(zap.spider.status()) < 100:
    print(f"Spidering: {zap.spider.status()}% complete")
    time.sleep(2)

# Configure and start active scanning
print(f"Starting active scan...")
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
