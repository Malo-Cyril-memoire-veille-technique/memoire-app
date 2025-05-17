import socket
import os
import json
import getpass
import threading
import time
import sys
from datetime import datetime
import hashlib
import uuid
import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import logging

LOG_FOLDER = "logs"
os.makedirs(LOG_FOLDER, exist_ok=True)

# Identifier dynamiquement le nom du conteneur
container_name = socket.gethostname().lower()

# Map explicite si tu veux renommer les logs selon le conteneur exact
if container_name == "client_a":
    log_file = "client-a.log"
elif container_name == "client_b":
    log_file = "client-b.log"
else:
    log_file = f"{container_name}.log"

log_path = os.path.join(LOG_FOLDER, log_file)

# Si jamais logs/client-a.log est un dossier par erreur
if os.path.isdir(log_path):
    os.rmdir(log_path)

# Configuration du logger
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(log_path, encoding='utf-8')
    ]
)

HOST = 'poc-server'
PORT = 5000
KEY_FOLDER = 'keys'
HISTORY_FOLDER = 'history'
os.makedirs(KEY_FOLDER, exist_ok=True)
os.makedirs(HISTORY_FOLDER, exist_ok=True)
KNOWN_KEYS_FOLDER = 'known_keys'
os.makedirs(KNOWN_KEYS_FOLDER, exist_ok=True)

session_token = None
username = ""
priv_key_path = ""
pub_key_path = ""
running = True

def send_request(data):
    """
    Envoie une requête au serveur et retourne la réponse.
    """
    try:
        action = data.get("action", "unknown")
        if action != "get_messages":
            logging.info(f"Requête envoyée : {action}")
            logging.debug(f"Contenu complet de la requête : {json.dumps(data, indent=2)}")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(json.dumps(data).encode())
            response = s.recv(8192).decode()

        if action != "get_messages":
            logging.info(f"Réponse reçue pour {action}")
            logging.debug(f"Contenu complet de la réponse : {response}")

        return response
    except Exception as e:
        logging.error(f"Erreur lors de l'envoi de la requête : {e}")
        return json.dumps({"status": "error", "message": str(e)})


def create_account():
    """
    Crée un compte utilisateur sur le serveur.
    Demande un nom d'utilisateur et un mot de passe.
    """
    global username
    username = input("Créer un nom d'utilisateur : ").strip()
    password = getpass.getpass("Créer un mot de passe : ").strip()
    logging.info(f"Création de compte pour {username}")
    response = send_request({"action": "register", "username": username, "password": password})
    try:
        result = json.loads(response)
    except json.JSONDecodeError:
        logging.error(f"Réponse non valide du serveur : {response}")
        print("[ERREUR] Réponse non valide du serveur :", response)
        return
    if result.get("status") == "ok":
        logging.info(f"Compte créé pour {username}")
        print("[INFO] Compte créé avec succès.")
    else:
        logging.error(f"Échec de création : {result.get('message')}")
        print("[ERREUR] Impossible de créer le compte :", result.get("message"))

def login():
    """
    Connexion de l'utilisateur et récupération du token de session.
    """
    global username, session_token, priv_key_path, pub_key_path
    username = input("Nom d'utilisateur : ").strip()
    password = getpass.getpass("Mot de passe : ").strip()
    logging.info(f"Connexion pour {username}")
    response = send_request({"action": "login", "username": username, "password": password})
    try:
        result = json.loads(response)
    except json.JSONDecodeError:
        logging.error(f"Réponse invalide à la connexion : {response}")
        print("[ERREUR] Réponse non valide du serveur :", response)
        return False
    if result.get("status") == "ok":
        session_token = result.get("token")
        priv_key_path = os.path.join(KEY_FOLDER, f"{username}_private.pem")
        pub_key_path = os.path.join(KEY_FOLDER, f"{username}_public.pem")
        load_keys()
        register_key()
        logging.info(f"Connexion réussie pour {username}")
        print("[INFO] Clé publique automatiquement enregistrée.")
        return True
    else:
        logging.error(f"Échec de connexion : {result.get('message')}")
        print("[ERREUR] Échec de la connexion :", result.get("message"))
        return False

def logout():
    """
    Déconnexion de l'utilisateur et suppression du token de session.
    """
    global session_token
    logging.info(f"Déconnexion de {username}")
    send_request({"action": "logout", "token": session_token})
    session_token = None

def generate_keys():
    """
    Génère une paire de clés RSA et les enregistre dans des fichiers PEM.
    """
    logging.info(f"Génération de clés pour {username}")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(priv_key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
    public_key = private_key.public_key()
    with open(pub_key_path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))
    logging.info(f"Clés sauvegardées : {priv_key_path}, {pub_key_path}")

def load_keys():
    """
    Charge les clés privées et publiques de l'utilisateur.
    Si elles n'existent pas, elles sont générées.
    """
    if not os.path.exists(priv_key_path) or not os.path.exists(pub_key_path):
        logging.info(f"Clés manquantes pour {username}, génération en cours...")
        generate_keys()
    else:
        logging.info(f"Clés déjà présentes pour {username}")
    with open(priv_key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(pub_key_path, 'rb') as f:
        public_key = f.read().decode()
    return private_key, public_key

def register_key():
    """
    Enregistre la clé publique de l'utilisateur sur le serveur.
    """
    _, pub_key_str = load_keys()
    logging.info(f"Envoi de la clé publique au serveur pour {username}")
    send_request({"action": "register_key", "token": session_token, "public_key": pub_key_str})

def get_key(target):
    """
    Récupère la clé publique du serveur, la compare à celle connue (si existante),
    et alerte en cas de modification (protection MITM).
    """
    logging.info(f"Récupération de la clé publique de {target}")
    response = send_request({"action": "get_key", "token": session_token, "target": target})
    result = json.loads(response)
    if result.get("status") != "ok":
        logging.warning(f"Clé publique de {target} introuvable sur le serveur.")
        return None

    server_key = result.get("key")
    key_path = os.path.join(KNOWN_KEYS_FOLDER, f"{target}.pem")

    # Si on connaît déjà cette clé, on vérifie qu'elle n'a pas changé
    if os.path.exists(key_path):
        with open(key_path, 'r') as f:
            known_key = f.read()
        if known_key != server_key:
            new_fp = hashlib.sha256(server_key.encode()).hexdigest().upper()
            old_fp = hashlib.sha256(known_key.encode()).hexdigest().upper()
            logging.warning(f"Clé publique de {target} modifiée !")
            logging.warning(f"Ancienne empreinte : {':'.join(old_fp[i:i+2] for i in range(0, len(old_fp), 2))}")
            logging.warning(f"Nouvelle empreinte : {':'.join(new_fp[i:i+2] for i in range(0, len(new_fp), 2))}")
            print(f"\nAVERTISSEMENT : La clé publique de {target} a changé !")
            print(f"Ancienne empreinte : {':'.join(old_fp[i:i+2] for i in range(0, len(old_fp), 2))}")
            print(f"Nouvelle empreinte : {':'.join(new_fp[i:i+2] for i in range(0, len(new_fp), 2))}")
            choice = input("Accepter cette nouvelle clé ? (o/n) : ").strip().lower()
            if choice != 'o':
                logging.info("Nouvelle clé refusée par l'utilisateur.")
                print("[INFO] Connexion annulée.")
                return None
            else:
                with open(key_path, 'w') as f:
                    f.write(server_key)
                logging.info("Nouvelle clé acceptée et enregistrée.")
    else:
        # Nouvelle clé, on enregistre
        with open(key_path, 'w') as f:
            f.write(server_key)
        logging.info(f"Clé publique de {target} enregistrée localement.")

    return server_key


def get_conversation_partners():
    """
    Récupère la liste des partenaires de discussion à partir du serveur.
    Déchiffre les messages pour identifier les expéditeurs.
    """
    private_key, _ = load_keys()
    logging.info("Récupération des partenaires de discussion...")
    raw = send_request({"action": "get_messages", "token": session_token})
    result = json.loads(raw)
    if result.get("status") != "ok":
        logging.warning("Échec lors de la récupération des messages.")
        return []

    messages = result.get("messages", [])
    logging.info(f"{len(messages)} message(s) récupéré(s) pour analyse.")
    partners = set()

    for item in messages:
        try:
            ciphertext = bytes.fromhex(item["message"])
            decrypted = private_key.decrypt(
                ciphertext,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            ).decode()

            if decrypted.startswith("FROM:"):
                parts = decrypted.split(":", 3)
                if len(parts) == 4:
                    partner = parts[1].strip()
                    partners.add(partner)
        except Exception as e:
            logging.debug(f"Erreur de déchiffrement ou parsing d'un message : {e}")
            continue

    logging.info(f"Partenaires identifiés : {sorted(partners)}")
    return sorted(partners)

def save_sent_message(recipient, timestamp, text):
    """
    Enregistre un message envoyé dans l'historique.
    """
    path = os.path.join(HISTORY_FOLDER, f"{username}_to_{recipient}.json")
    try:
        with open(path, 'r') as f:
            data = json.load(f)
    except:
        data = []
    data.append({"timestamp": timestamp, "sender": username, "text": text})
    with open(path, 'w') as f:
        json.dump(data, f)
    logging.info(f"Message envoyé enregistré : {username} ➜ {recipient}")

def save_received_message(sender, timestamp, text):
    """
    Enregistre un message reçu dans l'historique.
    """
    path = os.path.join(HISTORY_FOLDER, f"{sender}_to_{username}.json")
    try:
        with open(path, 'r') as f:
            data = json.load(f)
    except:
        data = []
    data.append({"timestamp": timestamp, "sender": sender, "text": text})
    with open(path, 'w') as f:
        json.dump(data, f)
    logging.info(f"Message reçu enregistré : {sender} ➜ {username}")

def load_sent_messages(recipient):
    """
    Charge les messages envoyés à un destinataire à partir de l'historique.
    """
    path = os.path.join(HISTORY_FOLDER, f"{username}_to_{recipient}.json")
    try:
        with open(path, 'r') as f:
            messages = json.load(f)
            logging.info(f"{len(messages)} message(s) envoyés chargés pour {recipient}")
            return messages
    except:
        logging.info(f"Aucun message trouvé pour {recipient}")
        return []

def load_sent_messages_from(sender):
    """
    Charge les messages envoyés par un expéditeur à partir de l'historique.
    """
    path = os.path.join(HISTORY_FOLDER, f"{sender}_to_{username}.json")
    try:
        with open(path, 'r') as f:
            messages = json.load(f)
            logging.info(f"{len(messages)} message(s) reçus chargés depuis {sender}")
            return messages
    except:
        logging.info(f"Aucun message trouvé depuis {sender}")
        return []


def fetch_live_messages(target):
    """
    Récupère les messages en temps réel pour un utilisateur donné.
    """
    global running
    private_key, _ = load_keys()
    seen_path = os.path.join(HISTORY_FOLDER, f"seen_{username}_from_{target}.json")
    try:
        with open(seen_path, 'r') as f:
            seen = set(json.load(f))
        logging.debug(f"Fichier seen chargé : {seen_path}, {len(seen)} messages déjà vus")
    except:
        seen = set()
        logging.info(f"Initialisation de la surveillance des messages de {target}")

    while running:
        raw = send_request({"action": "get_messages", "token": session_token})
        result = json.loads(raw)
        if result.get("status") == "ok":
            messages = result.get("messages", [])
            for item in messages:
                raw_message = json.dumps(item, sort_keys=True)
                if raw_message in seen:
                    continue  # ne log pas les messages déjà vus

                try:
                    ciphertext = bytes.fromhex(item["message"])
                    signature = bytes.fromhex(item["signature"])

                    decrypted = private_key.decrypt(
                        ciphertext,
                        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                    ).decode()

                    if decrypted.startswith("FROM:"):
                        parts = decrypted.split(":", 3)
                        sender = parts[1].strip()
                        timestamp = int(parts[2].strip())
                        text = parts[3].strip()

                        sender_key_pem = get_key(sender)
                        if not sender_key_pem:
                            logging.warning(f"Clé introuvable pour {sender}")
                            continue
                        key_bytes = sender_key_pem.encode()
                        fp = hashlib.sha256(key_bytes).hexdigest().upper()
                        formatted_fp = ':'.join(fp[i:i+2] for i in range(0, len(fp), 2))
                        logging.info(f"Empreinte SHA-256 de la clé publique de {target} : {formatted_fp}")

                        sender_public_key = serialization.load_pem_public_key(sender_key_pem.encode())
                        sender_public_key.verify(
                            signature,
                            decrypted.encode(),
                            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                            hashes.SHA256()
                        )

                        if sender == target:
                            # Affichage en direct + log seulement si nouveau
                            sys.stdout.write('\r' + ' ' * 80 + '\r')
                            print(f"[{datetime.fromtimestamp(timestamp).strftime('%H:%M')}] {sender} : {text}")
                            sys.stdout.write(f"{username} > ")
                            sys.stdout.flush()

                            logging.debug(f"Signature reçue (hex) : {item['signature']}")
                            logging.debug(f"Message chiffré reçu (hex) : {item['message']}")
                            logging.debug(f"Déchiffrement obtenu : {decrypted}")

                            save_received_message(sender, timestamp, text)
                            logging.debug(f"Signature reçue (hex) : {item['signature']}")
                            logging.debug(f"Message chiffré reçu (hex) : {item['message']}")
                            logging.debug(f"Déchiffrement obtenu : {decrypted}")
                            logging.info(f"Nouveau message reçu de {sender} à {datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')} → {text}")
                            seen.add(raw_message)

                except Exception as e:
                    logging.debug(f"Erreur traitement message : {e}")
                    continue

            with open(seen_path, 'w') as f:
                json.dump(list(seen), f)

        time.sleep(1)


def chat_session(target):
    """
    Gère une session de discussion avec un utilisateur donné.
    Envoie une copie chiffrée du message à l'autorité via une backdoor (key escrow).
    """
    global running
    private_key, _ = load_keys()
    logging.info(f"Démarrage session de chat avec {target}")
    print(f"\n[Conversation avec {target}] (tape 'exit' pour quitter)")
    
    key_pem = get_key(target)
    if not key_pem:
        print("[ERREUR] Clé du destinataire introuvable.")
        logging.error(f"Clé publique introuvable pour {target}")
        return
    public_key = serialization.load_pem_public_key(key_pem.encode())

    try:
        with open("authority_keys/authority_public.pem", "rb") as f:
            authority_key = serialization.load_pem_public_key(f.read())
    except FileNotFoundError:
        print("[ERREUR] Fichier 'authority_public.pem' manquant.")
        logging.error("Fichier 'authority_public.pem' introuvable.")
        return

    messages = load_sent_messages(target) + load_sent_messages_from(target)
    messages.sort(key=lambda m: m['timestamp'])
    for msg in messages:
        t = datetime.fromtimestamp(msg["timestamp"]).strftime("%H:%M")
        label = "moi" if msg["sender"] == username else msg["sender"]
        print(f"[{t}] {label} : {msg['text']}")

    running = True
    listener = threading.Thread(target=fetch_live_messages, args=(target,), daemon=True)
    listener.start()

    try:
        while True:
            msg = input(f"{username} > ")
            if msg.lower() == 'exit':
                logging.info(f"Fin de la session avec {target}")
                break

            now = int(datetime.now().timestamp())
            full_message = f"FROM:{username}:{now}:{msg}"

            signature = private_key.sign(
                full_message.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )

            ciphertext = public_key.encrypt(
                full_message.encode(),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )

            escrow_encrypted = authority_key.encrypt(
                full_message.encode(),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )

            message_id = uuid.uuid4().hex

            logging.info(f"Message clair à envoyer : {full_message}")
            logging.debug(f"Signature générée (hex) : {signature.hex()}")
            logging.debug(f"Message chiffré (hex) : {ciphertext.hex()}")
            logging.debug(f"Escrow chiffré (hex) : {escrow_encrypted.hex()}")

            payload = {
                "message": ciphertext.hex(),
                "signature": signature.hex(),
                "escrow": escrow_encrypted.hex(),
                "id": message_id
            }

            send_request({
                "action": "send_message",
                "token": session_token,
                "to": target,
                "message": json.dumps(payload)
            })

            logging.info(f"Message envoyé à {target} (ID: {message_id[:8]})")
            save_sent_message(target, now, msg)

    finally:
        running = False
        listener.join()

def discussion_menu():
    """
    Affiche le menu des discussions et permet de choisir une conversation.
    """
    while True:
        print("\n--- DISCUSSIONS ---")
        partners = get_conversation_partners()
        for i, partner in enumerate(partners):
            print(f"{i + 1}. {partner}")
        print("c. Nouvelle conversation")
        print("q. Retour")

        choice = input("> ").strip().lower()
        if choice == 'q':
            break
        elif choice == 'c':
            target = input("Nom de l'utilisateur : ").strip()
            chat_session(target)
        elif choice.isdigit() and 1 <= int(choice) <= len(partners):
            chat_session(partners[int(choice) - 1])
        else:
            print("[ERREUR] Choix invalide.")

def main_menu():
    """
    Affiche le menu principal et gère la création de compte et la connexion.
    """
    while True:
        print("\n--- MENU PRINCIPAL ---")
        print("1. Créer un compte")
        print("2. Se connecter")
        print("3. Quitter")
        choice = input("> ")
        if choice == '1':
            create_account()
        elif choice == '2':
            if login():
                user_menu()
        elif choice == '3':
            break
        else:
            print("[ERREUR] Choix invalide.")

def user_menu():
    """
    Affiche le menu utilisateur après connexion.
    """
    while True:
        print(f"\n[CLIENT: {username}] Menu")
        print("1. Discussions")
        print("2. Me déconnecter")
        choice = input("> ")
        if choice == '1':
            discussion_menu()
        elif choice == '2':
            logout()
            print("[INFO] Déconnecté.")
            break
        else:
            print("[ERREUR] Choix invalide.")

if __name__ == '__main__':
    main_menu()