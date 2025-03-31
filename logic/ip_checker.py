import socket
import dns.resolver
import requests

# Load clean IPs from file (500 genuine IPs)
CLEAN_IPS_FILE = "cleanip.txt"

def load_clean_ips():
    try:
        with open(r'C:\Users\akars\OneDrive\Desktop\PTI\logic\AFAT-Clean-IPs.txt', "r") as f:
            return set(line.strip() for line in f.readlines())
    except FileNotFoundError:
        print(f"⚠️ Warning: {CLEAN_IPS_FILE} not found!")
        return set()

CLEAN_IPS = load_clean_ips()

def check_ip(ip):
    """Analyzes an IP address for suspicious activity."""
    if ip in CLEAN_IPS:
        return "✅ Safe (Whitelisted)", "N/A", "N/A", "N/A"

    # Step 1: Get Geolocation Data
    location_info = get_geo_info(ip)

    # Step 2: Get ISP Information
    isp_info = location_info.get("ISP", "Unknown")

    # Step 3: Retrieve DNS Records
    dns_records = get_dns_records(ip)

    # Step 4: Determine Status
    is_suspicious = (location_info["Country"] == "N/A") or (dns_records == "No records")

    status = "⚠️ Suspicious!" if is_suspicious else "✅ Looks Safe"

    return status, f"{location_info['City']}, {location_info['Country']}", isp_info, dns_records


def get_geo_info(ip):
    """Fetch geolocation data using an external API."""
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/")
        data = response.json()
        return {
            "City": data.get("city", "Unknown"),
            "Country": data.get("country_name", "Unknown"),
            "ISP": data.get("org", "Unknown")
        }
    except requests.exceptions.RequestException:
        return {"City": "N/A", "Country": "N/A", "ISP": "N/A"}


def get_dns_records(ip):
    """Fetch DNS records for the given IP address."""
    try:
        domain = socket.gethostbyaddr(ip)[0]
        answers = dns.resolver.resolve(domain, "A")
        return [answer.to_text() for answer in answers]
    except (socket.herror, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return "No records"
