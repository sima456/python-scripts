import argparse
import requests
import json

# Define command line arguments using argparse
parser = argparse.ArgumentParser(description='Vulnerability assessment tool.')
parser.add_argument('hostname', type=str, help='The hostname to check for vulnerabilities')
args = parser.parse_args()

# Nessus API URL and credentials
nessus_url = "https://<nessus_server>/nessus"
nessus_access_key = "<access_key>"
nessus_secret_key = "<secret_key>"

# Retrieve scan results from Nessus API
response = requests.get(nessus_url + "/scans", auth=(nessus_access_key, nessus_secret_key))
if response.status_code == 200:
    scans = json.loads(response.content.decode())["scans"]
    for scan in scans:
        # Check if the scan matches the specified hostname
        if args.hostname in scan["name"]:
            scan_id = scan["id"]
            # Retrieve the vulnerability details for the specified scan ID
            response = requests.get(nessus_url + f"/scans/{scan_id}/vulnerabilities", auth=(nessus_access_key, nessus_secret_key))
            if response.status_code == 200:
                vulnerabilities = json.loads(response.content.decode())["vulnerabilities"]
                if len(vulnerabilities) > 0:
                    print("Vulnerabilities found for hostname", args.hostname)
                    print("========================================")
                    for vulnerability in vulnerabilities:
                        # Extract relevant vulnerability information
                        plugin_id = vulnerability["plugin_id"]
                        plugin_name = vulnerability["plugin_name"]
                        severity = vulnerability["severity"]
                        description = vulnerability["description"]
                        solution = vulnerability["solution"]

                        # Format the output
                        print("Plugin ID:", plugin_id)
                        print("Plugin Name:", plugin_name)
                        print("Severity:", severity)
                        print("Description:", description)
                        print("Solution:", solution)
                        print("========================================")
                else:
                    print("No vulnerabilities found for hostname", args.hostname)
            else:
                print("Error retrieving vulnerabilities from Nessus API")
else:
    print("Error retrieving scans from Nessus API")
