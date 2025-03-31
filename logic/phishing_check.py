import re
import requests

API_KEY = "4b84468a0e89bf239664d6bb7f653de5bca48a7d8e40b70b253bb4f0e032d11a"

def submit_url_to_virustotal(url):
    headers = {"x-apikey": API_KEY}
    data = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
    
    if response.status_code == 200:
        return response.json()["data"]["id"]
    return None

def get_url_report(url_id):
    headers = {"x-apikey": API_KEY}
    response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{url_id}", headers=headers)
    return response.json()

def check_url_reputation(url):
    url_id = submit_url_to_virustotal(url)
    if not url_id:
        return {"error": "Could not submit URL to VirusTotal"}

    return get_url_report(url_id)

def is_suspicious_url(url):
    patterns = [
        r"https?://.*[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",  # IP-based URLs
        r"https?://.*\bfree\b.*",  # Words like "free", "win", etc.
        r"https?://.*\bxn--\b.*",  # Punycode domains
    ]
    return any(re.search(pattern, url) for pattern in patterns)

def check_url(url):
    reputation = check_url_reputation(url)
    suspicious = is_suspicious_url(url)
    return reputation, suspicious
