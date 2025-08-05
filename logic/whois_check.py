import whois

def get_whois_info(domain):
    data = whois.whois(domain)  # ✅ Correct method
    creation_date = data.creation_date
    expiration_date = data.expiration_date
    registrar = data.registrar
    return creation_date, expiration_date, registrar
