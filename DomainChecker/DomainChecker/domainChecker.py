import dns.resolver
import os
import json
import re
from urllib.parse import urlparse
import requests

EXPORT_FOLDER = "Export"#Chemin de prod : "/opt/bitnami/apache/htdocs/DomainChecker/DomainChecker/Export" 

def validate_domain(input_value):
    parsed_url = urlparse(input_value)
    domain = parsed_url.netloc or parsed_url.path
    domain = domain.split(':')[0]  # Remove port if any

    # Extract base domain
    domain_parts = domain.split('.')
    if len(domain_parts) > 2:
        known_second_levels = ['co.uk', 'gov.uk', 'ac.uk', 'org.uk', 'com.au', 'co.in', 'com.br', 'co.jp', 'co.nz', 'co.za', 'com.sg', 'com.hk', 'com.ar', 'com.mx', 'com.tr', 'com.cn', 'com.tw', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn'] # Add more known second-level domains as needed
        second_level_domain = '.'.join(domain_parts[-2:])
        if second_level_domain in known_second_levels:
            domain = '.'.join(domain_parts[-3:])
        else:
            domain = '.'.join(domain_parts[-2:])

    if not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain):
        raise ValueError("L'URL ne contient pas de domaine valide.")

    return domain

def get_highest_iteration(domain):
    highest_iteration = 0
    for filename in os.listdir(EXPORT_FOLDER):
        if filename.startswith(domain):
            iteration_str = filename.split('_')[-1].split('.')[0]
            try:
                iteration = int(iteration_str)
                highest_iteration = max(highest_iteration, iteration)
            except ValueError:
                continue
    return highest_iteration

def evaluate_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if rdata.strings[0].startswith(b"v=spf1"):
                spf_record = rdata.strings[0].decode()
                mechanism_list = spf_record.split()[1:]  
                
                has_specific_mechanisms = any(mech for mech in mechanism_list if mech.startswith(('a', 'mx', 'ip4', 'ip6', 'include')))
                
               
                all_directive = next((mech for mech in mechanism_list if mech.endswith('all')), None)
                
                if has_specific_mechanisms:
                    base_score = 1  # Accorder 1/5 pour la présence de mécanismes spécifiques
                    if all_directive == "~all":
                        return f"{base_score + 4}/5"  # ~all est la meilleure pratique
                    elif all_directive == "-all":
                        return f"{base_score + 3}/5"  # -all est sécurisé mais peut affecter la délivrabilité
                    elif all_directive == "?all":
                        return f"{base_score + 1}/5"  # ?all est neutre
                    elif all_directive == "+all":
                        return f"{base_score}/5"  # +all est trop permissif, conserver la note de base
                    else:
                        # Si aucun "all" ou un autre mécanisme non standard est utilisé
                        return f"{base_score}/5"
                else:
                    return "0/5"         
        return "0/5"
    except Exception as e:
        return f"Erreur: {str(e)}"

        
COMMON_DKIM_SELECTORS = [
    "google", "default", "s1024", "s2048", "s4096", "mail", "smtp", "postfix", "sendmail", "exim",
    "domainkey", "dkim", "key1", "selector1", "selector2", "k1", "mailjet", "mandrill", "ses", "sendgrid",
    "smtpapi", "zoho", "outlook", "ms", "office365", "beta", "domk", "ei", "smtpout", "sm", "authsmtp",
    "alpha", "mesmtp", "cm", "prod", "pm", "gamma", "dkrnt", "dkimrnt", "private", "gmmailerd", "pmta",
    "x", "selector", "qcdkim", "postfix", "mikd", "main", "m", "dk20050327", "delta", "yibm", "wesmail",
    "test", "stigmate", "squaremail", "sitemail", "sasl", "sailthru", "responsys", "publickey", "proddkim",
    "mail-in", "mailrelay", "mail-dkim", "mailo", "lists", "iweb", "iport", "hubris", "googleapps", "gears",
    "exim4u", "exim", "et", "dyn", "duh", "dksel", "dkimmail", "corp", "centralsmtp", "ca", "bfi", "auth", "allselector", "zendesk1"
]

# Ajout de sélecteurs dynamiques
for i in range(1, 21):
    COMMON_DKIM_SELECTORS += [f"key{i}", f"yesmail{i}", f"selector{i}", f"m{i}"]

# Élimination des doublons potentiels
COMMON_DKIM_SELECTORS = list(set(COMMON_DKIM_SELECTORS))

def evaluate_dkim(domain):
    for selector in COMMON_DKIM_SELECTORS:
        dkim_record = f"{selector}._domainkey.{domain}"
        try:
            print(dkim_record)
            dns.resolver.resolve(dkim_record, 'TXT')
            return "Pass", dkim_record  # Retourne "Pass" dès qu'un enregistrement valide est trouvé
        except dns.resolver.NoAnswer:
            continue  # Passe au sélecteur suivant s'il n'y a pas de réponse
        except dns.resolver.NXDOMAIN:
            continue  # Passe si le domaine n'existe pas
        except Exception as e:
            print(f"Erreur inattendue pour le sélecteur {selector}: {e}")  # Pour le débogage
    return "Fail"  # Retourne "Fail" si aucun enregistrement valide n'a été trouvé pour tous les sélecteurs


def evaluate_dmarc(domain):
    dmarc_record = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_record, 'TXT')
        for rdata in answers:
            if rdata.strings[0].startswith(b"v=DMARC1"):
                policies = [part.strip().split('=') for part in rdata.strings[0].decode().split(';') if '=' in part]
                policy_dict = {key.strip(): value.strip() for key, value in policies if key.strip() == 'p'}
                policy = policy_dict.get('p', 'none')
                return policy
        return "none"
    except Exception as e:
        print(f"Error resolving DMARC record for {domain}: {e}")
        return "none"

def check_blacklist(domain):
    blacklist_services = ["zen.spamhaus.org"]
    listed_in = "none"
    for service in blacklist_services:
        try:
            query = '.'.join(reversed(domain.split('.'))) + '.' + service
            dns.resolver.resolve(query, 'A')
            listed_in = service
            break
        except dns.resolver.NXDOMAIN:
            continue
        except Exception:
            continue
    return listed_in

def evaluate_bimi(domain):
    score = 0  
    status = "Succès"

    try:
        answers = dns.resolver.resolve(f"default._bimi.{domain}", 'TXT')
        for rdata in answers:
            bimi_record = ''.join(part.decode('utf-8') for part in rdata.strings)
            if 'v=BIMI1;' in bimi_record:
                # Vérification de la présence et de l'accessibilité de l'URL du logo
                logo_url = bimi_record.split('l=')[1].split(';')[0].strip('"') if 'l=' in bimi_record else ""
                if logo_url and requests.head(logo_url, timeout=10).status_code == 200:
                    score += 1  # Ajout d'un point pour le logo accessible

                # Vérification de la présence de l'URL du VMC
                vmc_url = bimi_record.split('a=')[1].split(';')[0].strip('"') if 'a=' in bimi_record else ""
                if vmc_url:
                    score += 1  # Ajout d'un point pour la spécification du VMC

                break
    except dns.resolver.NoAnswer:
        status = f"Aucun enregistrement BIMI trouvé pour {domain}: {e}"
    except Exception as e:
        status = f"Erreur lors de la recherche de l'enregistrement BIMI pour {domain}: {e}"
        
    return f"{score}/2", status

def safe_file_write(domain, iteration_number, data):
    safe_domain = re.sub(r"[^a-zA-Z0-9.-]", "", domain)
    filename = f"{safe_domain}_{iteration_number}.json"
    filepath = os.path.join(EXPORT_FOLDER, filename)

    if os.path.commonpath([EXPORT_FOLDER, filepath]) != EXPORT_FOLDER:
        raise Exception("Tentative d'accès non autorisé au fichier.")

    with open(filepath, 'w') as file:
        json.dump(data, file, indent=4)

def main(domain):
    iteration_number = get_highest_iteration(domain) + 1
    
    dkim_status, dkim_record = evaluate_dkim(domain)
    bimi_score, bimi_status  = evaluate_bimi(domain)

    spf_result = evaluate_spf(domain)
    dkim_result = dkim_status
    dmarc_result = evaluate_dmarc(domain)
    blacklist_result = check_blacklist(domain)
    
    print(dkim_result)
    results = {
        "SPF": spf_result,
        "DKIM": dkim_result,
        "DMARC": dmarc_result,
        "Blacklist": blacklist_result,
        "BIMI":bimi_score,
 }

    safe_file_write(domain, iteration_number, results)

    return results

if __name__ == "__main__":
    try:
        input_value = input("Veuillez entrer le nom de domaine à évaluer : ")
        domain = validate_domain(input_value)
        print(f"Domaine validé : {domain}")
        results = main(domain)
        print(json.dumps(results, indent=4))
    except ValueError as e:
        print(e)

