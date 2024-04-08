from bottle import Bottle, request, response, redirect, HTTPError
import time
import domainChecker
import urllib.parse
import dnsExtractor

print("Démarrage de l'application")
app = Bottle()

request_counters = {}
REQUEST_LIMIT = 100
TIME_WINDOW = 60

@app.hook('before_request')
def rate_limiter():
    client_ip = request.environ.get('REMOTE_ADDR')
    current_time = time.time()
    expired_time = current_time - TIME_WINDOW
    for ip, (count, timestamp) in list(request_counters.items()):
        if timestamp < expired_time:
            del request_counters[ip]
    
    if client_ip in request_counters:
        count, timestamp = request_counters[client_ip]
        if count > REQUEST_LIMIT:
            response.status = 429  # Too Many Requests
            return "Trop de requêtes. Merci de réessayer plus tard."
        else:
            request_counters[client_ip] = (count + 1, current_time)
    else:
        request_counters[client_ip] = (1, current_time)

@app.route('/analyze', method='GET')
def get_analysis():
    domain = request.query.domain
    if not domain:
        return "Les champs domaine sont requis."
    
    validated_domain = domainChecker.validate_domain(domain)
    if not validated_domain:
        return "Le domaine fourni n'est pas valide."
    
    results = domainChecker.main(validated_domain)
    dns_records = dnsExtractor.extract_dns_records(validated_domain)

    params = {
        'domain': validated_domain,
        'results_spf': results.get('SPF', 'Non testé'),
        'results_dkim': results.get('DKIM', 'Non testé'),
        'results_dmarc': results.get('DMARC', 'Non testé'),
        'results_blacklist': results.get('Blacklist', 'Non testé'),
        'results_bimi': results.get('BIMI', 'Non testé'),
        'record_spf': dns_records.get('SPF', 'Non trouvé'),
        'record_dkim': dns_records.get('DKIM', 'Non trouvé'),
        'record_dmarc': dns_records.get('DMARC', 'Non trouvé'),
        'record_bimi': dns_records.get('BIMI', 'Non trouvé'),
    }
    results_params = urllib.parse.urlencode(params)
    redirect_url = f"https://growth-agence.com/domain-checker-results?{results_params}"
    return redirect(redirect_url)

application = app
