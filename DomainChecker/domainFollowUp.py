
import dns.resolver
import schedule
import time
import logging
from diagnosticExporter import save_results_to_json
import domainChecker as domainChecker

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialisation du compteur d'itérations pour chaque domaine
domain_iterations = {}

def run_tests(domain, selector):
    global domain_iterations
    domain_key = (domain, selector)
    
    domain_iterations[domain_key] = domain_iterations.get(domain_key, 0) + 1
    iteration_number = domain_iterations[domain_key]
    
    logging.info(f"--------------------------\nÉvaluation de {domain} (Itération {iteration_number}):")
    
    logging.info(f"Appel de domainChecker.main pour {domain} (Itération {iteration_number}):")
    results_score = domainChecker.main(domain, selector)
    
    results = {
        "domain": domain,
        "selector": selector,
        "iteration": iteration_number,
        "results": results_score   
    }

    filename = f"{domain}_{iteration_number}"  # Nom unique par itération
    save_results_to_json(filename, results)
    
    logging.info(f"Note globale: {results_score['Note_globale']:.2f}/10\n--------------------------")

def initial_report():
    for domain, selector in domains:
        run_tests(domain, selector)

def main():
    logging.info("Démarrage du suivi des domaines...")
    initial_report()

    logging.info("Planification des tests à exécuter périodiquement...")
    schedule.every().minute.do(initial_report)

    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("\nArrêt du script...")

if __name__ == "__main__":
    domains = [
        ("growth-agence.com","google"),
        ("example.net", "selector2")
    ]
    main()
