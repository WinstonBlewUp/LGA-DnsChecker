'''
from bottle import Bottle, request, redirect
import domainChecker  # Assurez-vous que domainChecker est accessible
import urllib.parse

app = Bottle()

@app.route('/analyze', method='GET')
def get_analysis():
    domain = request.query.domain
    selector = request.query.selector
    
    # Assumer que domain et selector sont déjà récupérés et validés
    results = domainChecker.main(domain, selector)  # Récupérer les résultats de domainChecker
    
    # Parser les résultats pour les injecter dans des variables adéquates
    # Supposons que results est un dictionnaire avec les clés 'SPF', 'DKIM', 'DMARC', etc.
    results_spf = results.get('SPF', 'Non testé')
    results_dkim = results.get('DKIM', 'Non testé')
    results_dmarc = results.get('DMARC', 'Non testé')
    results_blacklist = results.get('Blacklist', 'Non testé')
    
    # Encodage des résultats pour les passer dans l'URL
    params = {
        'results_spf': results_spf,
        'results_dkim': results_dkim,
        'results_dmarc': results_dmarc,
        'results_blacklist': results_blacklist,
    }
    results_params = urllib.parse.urlencode(params)
    
    # Construire l'URL de redirection vers la page Webflow avec les résultats en paramètres
    redirect_url = f"https://growth-agence.webflow.io/domain-checker-results?{results_params}"
    
    return redirect(redirect_url)

application = app  # Utilisé pour le déploiement avec un serveur WSGI
'''
