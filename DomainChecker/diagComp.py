import os
import re
import json

def find_latest_and_previous(domain, export_dir='Export'):
    pattern = re.compile(rf"{re.escape(domain)}_([0-9]+)\.json$")
    files = [f for f in os.listdir(export_dir) if pattern.match(f)]
    if not files:
        print("Aucun fichier trouvé pour ce domaine.")
        return None, None
    
    iterations = sorted([int(pattern.findall(f)[0]) for f in files])
    latest_iteration = iterations[-1]
    previous_iteration = iterations[-2] if len(iterations) > 1 else None
    
    latest_file = f"{domain}_{latest_iteration}.json"
    previous_file = f"{domain}_{previous_iteration}.json" if previous_iteration else None
    
    return os.path.join(export_dir, latest_file), os.path.join(export_dir, previous_file) if previous_file else None

def compare_json_files(latest_file, previous_file):
    if not previous_file:
        print("Aucune itération précédente à comparer.")
        return
    
    with open(latest_file, 'r') as f_latest, open(previous_file, 'r') as f_previous:
        latest_data = json.load(f_latest)
        previous_data = json.load(f_previous)
        
        # Effectuer votre comparaison ici. Par exemple, comparer les scores globaux.
        latest_score = latest_data.get('results', {}).get('Note_globale')
        previous_score = previous_data.get('results', {}).get('Note_globale')
        
        print(f"Comparaison des scores globaux : Dernière itération ({latest_score}) vs Itération précédente ({previous_score})")

if __name__ == "__main__":
    domain_to_check = input("Veuillez entrer le nom de domaine à évaluer : ")
    latest_file, previous_file = find_latest_and_previous(domain_to_check)
    
    if latest_file:
        print(f"Fichier le plus récent : {latest_file}")
        if previous_file:
            print(f"Fichier précédent : {previous_file}")
            compare_json_files(latest_file, previous_file)
        else:
            print("Il n'y a qu'une seule itération pour ce domaine.")
    else:
        print(f"Aucun fichier trouvé pour le domaine {domain_to_check}.")
