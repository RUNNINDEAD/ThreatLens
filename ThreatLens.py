import requests
import hashlib
import base64
import os

API_KEY = os.getenv("URLSCAN_API_KEY") or "APIKEY"

headers = {
    "API-Key": API_KEY
}


# -------------------------
# URL / DOMAIN SCAN
# -------------------------
def scan_url():
    url = input("\nEnter URL or domain: ").strip()

    url_id = base64.urlsafe_b64encode(
        hashlib.sha256(url.encode()).digest()
    ).decode().rstrip("=")

    api_url = f"https://api.urlscan.io/v1/result/{url_id}"

    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        verdict = data.get("verdicts", {}).get("overall", {})
        malicious = verdict.get("malicious", False)

        print(f"\n[+] URL: {url}")
        print(f"[+] Malicious: {malicious}")
    else:
        print("\n[-] No scan found or error occurred.")


# -------------------------
# IP LOOKUP (basic)
# -------------------------
def scan_ip():
    ip = input("\nEnter IP address: ").strip()

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()

        print("\n[+] IP Info:")
        print(f"Country: {data.get('country')}")
        print(f"Region: {data.get('regionName')}")
        print(f"ISP: {data.get('isp')}")
        print(f"Org: {data.get('org')}")
    except:
        print("[-] Failed to lookup IP.")


# -------------------------
# SHOW HEADERS
# -------------------------
def get_headers():
    url = input("\nEnter URL: ").strip()

    try:
        response = requests.get(url)
        print("\n[+] Response Headers:")
        for key, value in response.headers.items():
            print(f"{key}: {value}")
    except:
        print("[-] Failed to fetch headers.")


# -------------------------
# FILE SHA256
# -------------------------
def hash_file():
    path = input("\nEnter file path: ").strip()

    if not os.path.exists(path):
        print("[-] File not found.")
        return

    with open(path, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    print(f"\n[+] SHA256: {file_hash}")


# -------------------------
# MENU
# -------------------------
def menu():
    while True:
        print("\n==============================")
        print("   ZeroScope Recon Tool 🔍")
        print("==============================")
        print("1. Scan Domain / URL")
        print("2. Scan IP Address")
        print("3. Get Headers")
        print("4. File SHA256")
        print("5. Exit")

        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            scan_url()
        elif choice == "2":
            scan_ip()
        elif choice == "3":
            get_headers()
        elif choice == "4":
            hash_file()
        elif choice == "5":
            print("\nExiting...")
            break
        else:
            print("[-] Invalid option.")


# -------------------------
# RUN
# -------------------------
if __name__ == "__main__":
    menu()