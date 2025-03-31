import whois

def get_whois_info(domain):
    w = whois.Whois(domain)  # Alternative approach
    return str(w.creation_date), str(w.expiration_date), w.registrar
