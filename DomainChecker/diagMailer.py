import os
import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def find_latest_file(domain_name, directory="Export"):
    matching_files = []
    for file in os.listdir(directory):
        if file.endswith(".json") and domain_name in file:
            try:
                iteration_num = int(file.split('_')[-1].split('.')[0])
                matching_files.append((file, iteration_num))
            except ValueError:
                continue

    if matching_files:
        latest_file = max(matching_files, key=lambda x: x[1])[0]
        return os.path.join(directory, latest_file)
    else:
        return None

def read_json_file(file_path):
    if file_path:
        with open(file_path, 'r') as file:
            return json.load(file)
    else:
        return "No matching file found."

def send_email(subject, body, recipient):
    sender_email = "robin@growth-agence.com"
    sender_password = "321Soleil.growth" 
    smtp_server = "smtp.gmail.com"
    smtp_port = 587  # Port pour TLS

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(sender_email, sender_password)
    text = msg.as_string()
    server.sendmail(sender_email, recipient, text)
    server.quit()

domain_name = input("Entrez le nom de domaine : ")
recipient_email = input("Entrez l'adresse e-mail du destinataire : ")  # Demande l'adresse e-mail du destinataire
latest_file_path = find_latest_file(domain_name)
json_content = read_json_file(latest_file_path)

if json_content != "No matching file found.":
    content_str = json.dumps(json_content, indent=4)
    send_email("Contenu JSON récupéré", content_str, recipient_email)  # Utilise l'adresse e-mail saisie par l'utilisateur
    print(f"Le contenu du fichier {latest_file_path} a été envoyé à {recipient_email}.")
else:
    print(json_content)
