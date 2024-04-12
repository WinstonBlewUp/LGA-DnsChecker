import json
import os

def save_results_to_json(filename, data):
    # Chemin du dossier où sauvegarder les fichiers
    export_folder = os.path.join(os.path.dirname(__file__), 'Export')
    os.makedirs(export_folder, exist_ok=True)  # Crée le dossier s'il n'existe pas

    file_path = os.path.join(export_folder, f"{filename}.json")
    with open(file_path, 'w') as json_file:
        json.dump(data, json_file, indent=4)
