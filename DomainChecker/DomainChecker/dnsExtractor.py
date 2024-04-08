import dns.resolver
import json
import domainChecker
import urllib.parse


def get_spf_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if rdata.strings[0].startswith(b"v=spf1"):
                return rdata.strings[0].decode()
    except Exception as e:
        print(f"Erreur lors de l'extraction de l'enregistrement SPF : {e}")
    return "Non trouvé"

COMMON_DKIM_SELECTORS = ["google", "default", "s1024", "s2048", "s4096"]

def get_dkim_record(domain):
    for selector in COMMON_DKIM_SELECTORS:
        dkim_record_name = f"{selector}._domainkey.{domain}"
        try:
            answers = dns.resolver.resolve(dkim_record_name, 'TXT')
            for rdata in answers:
                dkim_record = ''.join(part.decode('utf-8') for part in rdata.strings)
                return dkim_record
        except dns.resolver.NoAnswer:
            continue
        except Exception as e:
            print(f"Erreur lors de la recherche de l'enregistrement DKIM avec le sélecteur {selector}: {e}")
            continue
    return "Non trouvé"  # Aucun enregistrement DKIM trouvé pour les sélecteurs testés

def get_dmarc_record(domain):
    try:
        dmarc_record_name = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_record_name, 'TXT')
        for rdata in answers:
            if rdata.strings[0].startswith(b"v=DMARC1"):
                return rdata.strings[0].decode()
    except Exception as e:
        print(f"Erreur lors de l'extraction de l'enregistrement DMARC : {e}")
    return "Non trouvé"

def get_bimi_record(domain):
    try:
        # Utilisation du préfixe "default" comme dans evaluate_bimi
        answers = dns.resolver.resolve(f"default._bimi.{domain}", 'TXT')
        for rdata in answers:
            bimi_record = ''.join(part.decode('utf-8') for part in rdata.strings)
            # Vérification de la présence de la version BIMI dans l'enregistrement
            if 'v=BIMI1;' in bimi_record:
                return bimi_record  # Retourne l'enregistrement si valide
            else:
                return "Enregistrement trouvé, mais non valide"
    except dns.resolver.NoAnswer:
        return "Aucun enregistrement BIMI trouvé"
    except Exception as e:
        return f"Erreur lors de l'extraction : {e}"

    return "Non trouvé"


def extract_dns_records(domain):
    spf_record = get_spf_record(domain)
    dkim_record = get_dkim_record(domain)
    dmarc_record = get_dmarc_record(domain)
    bimi_record = get_bimi_record(domain)

def compare_records():
    
   
    return {
        "SPF": spf_record,
        "DKIM": dkim_record,
        "DMARC": dmarc_record,
        "BIMI": bimi_record,
    }
