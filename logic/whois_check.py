import whois as pythonwhois

def get_whois_info(domain):
    w = pythonwhois.whois(domain)
    return str(w.creation_date), str(w.expiration_date), w.registrar
