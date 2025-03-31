from flask import Flask, render_template, request
import re
import socket
import whois
import dns.resolver
from difflib import SequenceMatcher

app = Flask(__name__)

# ✅ List of known free email providers
FREE_EMAIL_PROVIDERS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com"}

# ✅ List of known disposable email domains
DISPOSABLE_EMAIL_DOMAINS = {"tempmail.com", "mailinator.com", "10minutemail.com"}

# ✅ List of high-profile domains (to detect impersonation attacks)
HIGH_PROFILE_DOMAINS = {"paypal.com", "amazon.com", "microsoft.com", "apple.com", "bankofamerica.com"}

# ✅ Common English words & names to avoid flagging real users
COMMON_WORDS = {"john", "michael", "alice", "david", "karan", "suresh", "emma", "akash", "saklani", "akarsh"}

### 🔹 Function 1: Check if the domain is disposable
def is_disposable_email(email):
    domain = email.split('@')[-1]
    return domain in DISPOSABLE_EMAIL_DOMAINS

### 🔹 Function 2: Detect suspicious/randomized usernames (Improved)
def is_suspicious_email(email):
    username, domain = email.split('@')

    # ✅ Allow usernames containing common words or names
    if any(word in username.lower() for word in COMMON_WORDS):
        return False

    # ⚠️ Check for overly random usernames (like "xj2kd93hf7@xyz.com") **but allow numbers**
    if re.fullmatch(r"[a-zA-Z0-9]{15,}", username):  
        return True  # Randomized usernames

    # ⚠️ Check if domain is pretending to be a well-known brand (Levenshtein Distance)
    for legit_domain in HIGH_PROFILE_DOMAINS:
        similarity = SequenceMatcher(None, domain, legit_domain).ratio()
        if similarity > 0.8 and domain != legit_domain:
            return True  # Looks like a fake version of a high-profile domain

    return False  # If none of the suspicious patterns matched, it's likely fine.

### 🔹 Function 3: Check if domain has valid mail servers (MX Record)
def has_valid_mx_record(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return len(mx_records) > 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return False

### 🔹 Function 4: WHOIS Lookup (Checking domain age & registrar)
def check_whois(email):
    domain = email.split('@')[-1]
    try:
        domain_info = whois.whois(domain)
        if isinstance(domain_info.creation_date, list):
            creation_date = domain_info.creation_date[0]  # Some WHOIS queries return a list
        else:
            creation_date = domain_info.creation_date

        return {
            "domain": domain,
            "creation_date": creation_date,
            "registrar": domain_info.registrar
        }
    except Exception:
        return {"domain": domain, "error": "WHOIS lookup failed"}

### 🔹 Function 5: **Main Analysis Function**
def analyze_email(email):
    domain = email.split('@')[-1]

    result = {
        "email": email,
        "disposable": is_disposable_email(email),
        "suspicious_format": is_suspicious_email(email),
        "valid_mx": has_valid_mx_record(domain),
        "whois": check_whois(email),
    }

    # Final Decision Logic
    if result["disposable"]:
        verdict = "❌ Suspicious (Disposable Email)"
        phishing = True
    elif not result["valid_mx"]:
        verdict = "❌ Suspicious (No Valid MX Record - Likely Fake)"
        phishing = True
    elif result["suspicious_format"]:
        verdict = "⚠️ Warning (Unusual Username or Impersonation)"
        phishing = True
    else:
        verdict = "✅ Genuine (No major red flags detected)"
        phishing = False

    result["verdict"] = verdict
    return result, phishing
