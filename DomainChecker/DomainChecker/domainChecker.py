import dns.resolver
import os
import json
import re
from urllib.parse import urlparse
import requests

EXPORT_FOLDER = "/opt/bitnami/apache/htdocs/DomainChecker/DomainChecker/Export"

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
                specific_mechanisms = [mech for mech in mechanism_list if mech.startswith(('a', 'mx', 'ip4', 'ip6', 'include', 'all', '-all', '~all', '?all'))]
                score = min(len(specific_mechanisms), 5)
                return f"{score}/5"
        return "0/5"
    except Exception:
        return "Erreur"

COMMON_DKIM_SELECTORS = ["google", "default", "s1024", "s2048", "s4096"]
def evaluate_dkim(domain):
    for selector in COMMON_DKIM_SELECTORS:
        dkim_record = f"{selector}._domainkey.{domain}"
        try:
            dns.resolver.resolve(dkim_record, 'TXT')
            return "Pass"
        except Exception:
            continue
    return "Fail"

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
    score = 0  # Initialisation du score

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
        print(f"Aucun enregistrement BIMI trouvé pour {domain}.")
    except Exception as e:
        print(f"Erreur lors de la recherche de l'enregistrement BIMI pour {domain}: {e}")

    return f"{score}/2"

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

    spf_result = evaluate_spf(domain)
    dkim_result = evaluate_dkim(domain)
    dmarc_result = evaluate_dmarc(domain)
    blacklist_result = check_blacklist(domain)
    bimi_score = evaluate_bimi(domain)

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

