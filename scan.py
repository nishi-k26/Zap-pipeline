import yaml
from zapv2 import ZAPv2
import time
import requests
import os
from datetime import datetime

api_key = os.getenv('API_KEY')
# Load the YAML configuration
with open("config.yml", "r") as config_file:
    config = yaml.safe_load(config_file)

# Extract data from YAML
website_url = config["website_url"]
username = config["username"]
password = config["password"]
scan_settings = config["scan_settings"]
attack_mode = scan_settings["attack_mode"]
scan_type = scan_settings["scan_type"]
max_depth = scan_settings["max_depth"]

# Start ZAP session
zap = ZAPv2(apikey=api_key)

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

# Wait for spidering to finish (this is just an example, you may need to adjust this logic)
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

# Save vulnerabilities to a YAML file
print("Saving vulnerabilities to scan_results.yml...")
scan_results = {
    "scan_metadata": {
        "target_url": website_url,
        "timestamp": datetime.now().isoformat(),
        "scan_type": scan_policy,
        "total_alerts": len(alerts)
    },
    "vulnerabilities": []
}

if alerts:
    for alert in alerts:
        vulnerability = {
            "risk_level": alert.get('risk'),
            "name": alert.get('name'),
            "description": alert.get('description'),
            "solution": alert.get('solution'),
            "url": alert.get('url'),
            "parameter": alert.get('param'),
            "evidence": alert.get('evidence'),
            "confidence": alert.get('confidence')
        }
        scan_results["vulnerabilities"].append(vulnerability)

# Write to YAML file
with open("scan_results.yml", "w") as yaml_file:
    yaml.safe_dump(scan_results, yaml_file, default_flow_style=False, sort_keys=False, allow_unicode=True)

print("Results saved to scan_results.yml")

