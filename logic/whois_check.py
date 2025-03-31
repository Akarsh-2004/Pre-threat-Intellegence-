import whois

def get_whois_info(domain):
    w = whois.whois(domain)
    return str(w.creation_date), str(w.expiration_date), w.registrar
