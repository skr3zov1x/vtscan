#v5
import sys
import hashlib
import requests
import json
import os

# Figure out where the script/executable is actually running from
APP_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
CONFIG_PATH = os.path.join(APP_DIR, "config.json")

def print_banner():
    banner = """
██    ██ ████████ ███████  ██████  █████  ███    ██ 
██    ██    ██    ██      ██      ██   ██ ████   ██ 
██    ██    ██    ███████ ██      ███████ ██ ██  ██ 
 ██  ██     ██         ██ ██      ██   ██ ██  ██ ██ 
  ████      ██    ███████  ██████ ██   ██ ██   ████ 
                                                    
A VIRUSTOTAL BASED FILE SCANNER BY @skr3zov1x
"""
    print(banner)

def get_api_key():
    # Check if we already saved the key
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                config = json.load(f)
                return config.get("api_key")
        except Exception:
            pass
            
    # First time setup: Ask the user via the console
    print("\n=== First-Time Setup ===")
    api_key = input("Please paste your VirusTotal API key: ").strip()
    
    # Save it immediately for next time
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump({"api_key": api_key}, f)
        print(f"API key successfully saved locally to: {CONFIG_PATH}\n")
    except Exception as e:
        print(f"Warning: Could not save configuration file: {e}")
        
    return api_key

def get_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error reading file: {e}")
        return None

def check_virustotal(file_hash, api_key):
    if not api_key:
        print("Error: No API key provided.")
        return

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        attributes = data['data']['attributes']
        stats = attributes['last_analysis_stats']
        results = attributes['last_analysis_results']
        
        print("\n=== Scan Summary ===")
        print(f"Malicious:  {stats['malicious']}")
        print(f"Suspicious: {stats['suspicious']}")
        print(f"Undetected: {stats['undetected']}")
        
        print("\n--- Vendor Breakdown ---")
        
        # Group results by their category
        grouped_results = {}
        for vendor, details in results.items():
            category = details.get('category', 'unknown')
            if category not in grouped_results:
                grouped_results[category] = []
            grouped_results[category].append((vendor, details))
            
        # Define the order in which categories should be printed
        category_order = ['malicious', 'suspicious', 'undetected', 'harmless', 'timeout', 'type-unsupported', 'unknown']
        
        # Print each group
        for category in category_order:
            if category in grouped_results:
                # Sort vendors alphabetically within their category
                category_items = sorted(grouped_results[category], key=lambda x: x[0])
                
                print(f"\n{category.capitalize()} : {len(category_items)}")
                
                for index, (vendor, details) in enumerate(category_items, start=1):
                    # Get the specific malware name, or default to "Clean" if none exists
                    verdict = details.get('result')
                    if not verdict:
                        verdict = "Clean" if category in ['undetected', 'harmless'] else category.capitalize()
                        
                    print(f"  {index}) {vendor} : {verdict}")
                
    elif response.status_code == 404:
        print("\nFile hash not found in the VirusTotal database.")
    elif response.status_code == 401:
        print("\nInvalid API key. Delete config.json to reset it.")
    elif response.status_code == 429:
        print("\nAPI Rate limit exceeded; please wait a minute.")
    else:
        print(f"\nError connecting to the service: {response.status_code}")

if __name__ == "__main__":
    try:
        print_banner()
        
        if len(sys.argv) < 2:
            print("Usage: Right-click a file and select 'Scan with VirusTotal'")
        else:
            file_path = sys.argv[1]
            print(f"Scanning: {file_path}...\n")
            
            api_key = get_api_key()
            file_hash = get_hash(file_path)
            
            if file_hash and api_key:
                check_virustotal(file_hash, api_key)
    except Exception as e:
        print(f"\nCRITICAL CRASH: {e}")
    
    input("\nPress Enter to exit...")