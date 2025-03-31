import whois  # Make sure python-whois is installed

def get_whois_info(domain):
    w = whois.query(domain)  # Use query() instead of whois()
    return str(w.creation_date), str(w.expiration_date), w.registrar
