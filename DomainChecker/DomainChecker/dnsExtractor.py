import dns.resolver
import json
from domainChecker import evaluate_dkim
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

def get_dkim_record(domain):
    status, dkim_record_name = evaluate_dkim(domain)
    if status == "Pass":
        try:
            # Interroger le DNS pour obtenir l'enregistrement DKIM
            answers = dns.resolver.resolve(dkim_record_name, 'TXT')
            for rdata in answers:
                # Concaténation et décodage des parties de l'enregistrement TXT
                dkim_record_content = ''.join(part.decode('utf-8') for part in rdata.strings)
                print(f"Enregistrement DKIM trouvé : {dkim_record_content}")
                return dkim_record_content
        except Exception as e:
            print(f"Erreur lors de la récupération de l'enregistrement DKIM pour {dkim_record_name}: {e}")
            return None
    else:
        print("Aucun enregistrement DKIM valide trouvé")
        return None

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
                print(bimi_record)
                return bimi_record 
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

    return spf_record, dkim_record, dmarc_record, bimi_record

def clean_spf(record):
    cleaned_parts = []
    include_found = False  
    for part in record.split():
        if part.lower().strip().startswith("include:"):
            if not include_found:  
                cleaned_parts.append("include:")
                include_found = True  # Marquer qu'un "include:" a été trouvé
        else:
            cleaned_parts.append(part.strip())

    spf_clean = " ".join(cleaned_parts)
    return spf_clean


def clean_dkim(record):
    cleaned_parts = []
    for part in record.split(";"):
        if part.lower().strip().startswith("p="):
            cleaned_parts.append("p=")
        else:
            cleaned_parts.append(part.strip())
    
    dkim_clean = ";".join(cleaned_parts)
    
    return dkim_clean

def clean_dmarc(record):
    cleaned_parts = []
    for part in record.split(";"):
        # Ignorer les parties commençant par "pct="
        if part.lower().strip().startswith("pct="):
            continue
        elif part.lower().strip().startswith("rua=") or part.lower().strip().startswith("ruf="):
            cleaned_parts.append(part.split("=")[0] + "=")
        else:
            cleaned_parts.append(part.strip())

    dmarc_clean = ";".join(cleaned_parts)
    
    return dmarc_clean


def clean_bimi(record):
    cleaned_parts = []
    for part in record.split(";"):
        if part.lower().strip().startswith("l=") or part.lower().strip().startswith("a="):
            cleaned_parts.append(part.split("=")[0] + "=")  # Conserver l'instruction sans son contenu
        else:
            cleaned_parts.append(part.strip())
    
    bimi_clean = ";".join(cleaned_parts)
    
    return bimi_clean
 
def compare_records(domain):

    spf_record, dkim_record, dmarc_record, bimi_record = extract_dns_records(domain)

    spf_ref = "v=spf1 include:_example.com ~all"
    dkim_ref = "v=DKIM1; k=rsa; p=example"
    dmarc_ref = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:dmarc@example.com; fo=1;"
    bimi_ref = "v=BIMI1; l=https://example.com/bimi.svg; a=@example.com"


    record_clean = [
        clean_spf(spf_record),
        clean_dkim(dkim_record),
        clean_dmarc(dmarc_record),
        clean_bimi(bimi_record),
    ]

    ref_clean = [
        clean_spf(spf_ref),
        clean_dkim(dkim_ref),
        clean_dmarc(dmarc_ref),
        clean_bimi(bimi_ref),
    ]
    print(record_clean)
    
    def find_differences(str1, str2):
    
        if "v=spf1" in str1 or "v=spf1" in str2:
            tokens1 = str1.split(' ')
            tokens2 = str2.split(' ')
        else:
            tokens1 = [token + ';' for token in str1.split(';') if token]
            tokens2 = [token + ';' for token in str2.split(';') if token]
    
        result1 = ''
        result2 = ''

        max_len = max(len(tokens1), len(tokens2))
        for i in range(max_len):
            token1 = tokens1[i] if i < len(tokens1) else ''
            token2 = tokens2[i] if i < len(tokens2) else ''
            
            if token1 != token2:
                if not (token1 in token2 or token2 in token1):
                    result1 += token1 + (' ' if "v=spf1" in str1 else '')
                    result2 += token2 + (' ' if "v=spf1" in str2 else '')


        return result1.strip('; ').rstrip(), result2.strip('; ').rstrip()
    
    differences = {
        'SPF': {'record': '', 'reference': ''},
        'DKIM': {'record': '', 'reference': ''},
        'DMARC': {'record': '', 'reference': ''},
        'BIMI': {'record': '', 'reference': ''}
    }

    record_types = ['SPF', 'DKIM', 'DMARC', 'BIMI']

    for i, record_type in enumerate(record_types):
        record = record_clean[i]
        reference = ref_clean[i]
        diff_record, diff_reference = find_differences(record, reference)

        differences[record_type]['record'] = diff_record
        differences[record_type]['reference'] = diff_reference

    return differences
    
if __name__ == "__main__":
    domain_input = input("Veuillez entrer le nom de domaine à évaluer : ")
    diffs = compare_records(domain_input.strip())

    for record_type in diffs:
        print(f"Differences in {record_type} record: {diffs[record_type]['record']}")
        print(f"Differences in {record_type} reference: {diffs[record_type]['reference']}")