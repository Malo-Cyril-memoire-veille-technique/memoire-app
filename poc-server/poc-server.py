import socket
import threading
import os
import json
import uuid
import hashlib
import time
import logging

LOG_FOLDER = "logs"
os.makedirs(LOG_FOLDER, exist_ok=True)

# Configuration des logs
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_FOLDER, "server.log")),
    ]
)

HOST = '0.0.0.0'
PORT = 5000
DATA_FOLDER = 'data'
USERS_FILE = os.path.join(DATA_FOLDER, 'users.json')
SESSIONS_FILE = os.path.join(DATA_FOLDER, 'sessions.json')
KEYS_FILE = os.path.join(DATA_FOLDER, 'public_keys.json')
MESSAGES_FILE = os.path.join(DATA_FOLDER, 'messages.json')

os.makedirs(DATA_FOLDER, exist_ok=True)

for file in [USERS_FILE, SESSIONS_FILE, KEYS_FILE, MESSAGES_FILE]:
    if not os.path.exists(file):
        with open(file, 'w') as f:
            json.dump({}, f)

def load_json(path):
    """
    Charge un fichier JSON et renvoie son contenu sous forme de dictionnaire.
    """
    with open(path, 'r') as f:
        return json.load(f)

def save_json(path, data):
    """
    Enregistrer des données dans un fichier JSON.
    Si le fichier n'existe pas, le créer.
    Si le fichier existe, écraser son contenu.
    """
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

def handle_client(conn):
    """
    Gérer la connexion d'un client.
    Traiter les requêtes JSON envoyées par le client.
    """
    with conn:
        data = conn.recv(8192).decode()
        if not data:
            return
        try:
            req = json.loads(data)
        except json.JSONDecodeError:
            logging.error("❌ Requête JSON invalide reçue.")
            conn.sendall(json.dumps({"status": "error", "message": "invalid json"}).encode())
            return

        action = req.get("action")
        if action != "get_messages":
            logging.info(f"📩 Action reçue : {action}")

        if action == "register":
            username = req.get("username")
            password = req.get("password")
            logging.info(f"🆕 Tentative d'inscription : {username}")
            if not username or not password:
                conn.sendall(json.dumps({"status": "error", "message": "missing credentials"}).encode())
                return
            users = load_json(USERS_FILE)
            if username in users:
                logging.warning(f"⚠️ Utilisateur déjà existant : {username}")
                conn.sendall(json.dumps({"status": "error", "message": "username already exists"}).encode())
                return
            hashed_pw = hashlib.sha256(password.encode()).hexdigest()
            users[username] = hashed_pw
            save_json(USERS_FILE, users)
            logging.info(f"✅ Inscription réussie pour {username} (hash: {hashed_pw})")
            conn.sendall(json.dumps({"status": "ok", "message": "user created"}).encode())

        elif action == "login":
            username = req.get("username")
            password = req.get("password")
            logging.info(f"🔐 Tentative de connexion : {username}")
            if not username or not password:
                conn.sendall(json.dumps({"status": "error", "message": "missing credentials"}).encode())
                return
            users = load_json(USERS_FILE)
            hashed_input = hashlib.sha256(password.encode()).hexdigest()
            logging.info(f"🔎 Hash du mot de passe fourni : {hashed_input}")
            if username not in users:
                logging.error(f"❌ Utilisateur inconnu : {username}")
                conn.sendall(json.dumps({"status": "error", "message": "unknown user"}).encode())
                return
            if hashed_input != users[username]:
                logging.error(f"❌ Mauvais mot de passe pour : {username}")
                conn.sendall(json.dumps({"status": "error", "message": "invalid password"}).encode())
                return
            sessions = load_json(SESSIONS_FILE)
            token = str(uuid.uuid4())
            sessions[token] = username
            save_json(SESSIONS_FILE, sessions)
            logging.debug(f"🆔 Token généré pour {username} : {token}")
            logging.info(f"✅ Connexion réussie pour {username} (token {token})")
            conn.sendall(json.dumps({"status": "ok", "token": token}).encode())

        elif action == "logout":
            token = req.get("token")
            sessions = load_json(SESSIONS_FILE)
            user = sessions.pop(token, None)
            if user:
                logging.info(f"🔓 Déconnexion de : {user}")
                keys = load_json(KEYS_FILE)
                keys.pop(user, None)
                save_json(KEYS_FILE, keys)
            save_json(SESSIONS_FILE, sessions)
            conn.sendall(json.dumps({"status": "ok"}).encode())

        elif action == "register_key":
            token = req.get("token")
            public_key = req.get("public_key")
            sessions = load_json(SESSIONS_FILE)
            user = sessions.get(token)
            logging.info(f"📥 Requête d’enregistrement de clé publique pour {user}")
            if not user or not public_key:
                logging.error("❌ Échec enregistrement de clé (token/clé manquant)")
                conn.sendall(json.dumps({"status": "error", "message": "unauthorized or missing key"}).encode())
                return
            keys = load_json(KEYS_FILE)
            keys[user] = public_key
            logging.debug(f"🔎 Clé publique reçue (brut PEM) :\n{public_key}")
            save_json(KEYS_FILE, keys)
            logging.info(f"🔑 Clé publique enregistrée pour {user} :\n{public_key}")
            conn.sendall(json.dumps({"status": "ok"}).encode())

        elif action == "send_message":
            token = req.get("token")
            to = req.get("to")
            message = req.get("message")
            sessions = load_json(SESSIONS_FILE)
            sender = sessions.get(token)
            if not sender or not to or not message:
                logging.error("❌ Message refusé (informations manquantes)")
                conn.sendall(json.dumps({"status": "error", "message": "missing or unauthorized"}).encode())
                return
            try:
                parsed_message = json.loads(message)
            except json.JSONDecodeError:
                logging.error("❌ Format de message invalide")
                conn.sendall(json.dumps({"status": "error", "message": "invalid message format"}).encode())
                return

            cipher = parsed_message.get("message") or parsed_message.get("ciphertext")
            signature = parsed_message.get("signature")
            escrow = parsed_message.get("escrow")
            msg_id = parsed_message.get("id")
            encryption = parsed_message.get("encryption", "RSA-OAEP")
            signature_algo = parsed_message.get("signature_algo", "RSA-PSS")

            logging.info(f"📤 Nouveau message reçu de {sender} à destination de {to}")
            logging.debug(f"🔒 Payload brut reçu (str) : {message}")
            logging.debug("📦 Payload déstructuré (parsed):")
            logging.debug(f" - ID du message : {msg_id}")
            logging.debug(f" - Méthode de chiffrement : {encryption}")
            logging.debug(f" - Algorithme de signature : {signature_algo}")
            logging.debug(f" - Chiffrement destinataire (hex) : {cipher}")
            logging.debug(f" - Signature (hex) : {signature}")
            logging.debug(f" - Escrow (hex) : {escrow}")

            msgs = load_json(MESSAGES_FILE)
            msgs.setdefault(to, []).append(parsed_message)
            save_json(MESSAGES_FILE, msgs)
            logging.info(f"✅ Message stocké pour {to} (ID: {msg_id})")
            conn.sendall(json.dumps({"status": "ok"}).encode())


        elif action == "get_messages":
            token = req.get("token")
            sessions = load_json(SESSIONS_FILE)
            user = sessions.get(token)
            if not user:
                conn.sendall(json.dumps({"status": "error", "message": "unauthorized"}).encode())
                return
            msgs = load_json(MESSAGES_FILE)
            user_msgs = msgs.get(user, [])
            conn.sendall(json.dumps({"status": "ok", "messages": user_msgs}).encode())

        elif action == "get_key":
            token = req.get("token")
            target = req.get("target")
            sessions = load_json(SESSIONS_FILE)
            if token not in sessions:
                logging.error("❌ Requête get_key rejetée (token invalide)")
                conn.sendall(json.dumps({"status": "error", "message": "unauthorized"}).encode())
                return
            keys = load_json(KEYS_FILE)
            key = keys.get(target)
            if key:
                logging.info(f"🔍 Clé publique renvoyée pour {target} :\n{key}")
                conn.sendall(json.dumps({"status": "ok", "key": key}).encode())
            else:
                logging.warning(f"❌ Clé publique introuvable pour {target}")
                conn.sendall(json.dumps({"status": "error", "message": "key not found"}).encode())

        else:
            logging.warning(f"❓ Action inconnue : {action}")
            conn.sendall(json.dumps({"status": "error", "message": "unknown action"}).encode())

def start_server():
    """
    Démarrer le serveur TCP.
    Écoute les connexions entrantes et gère les requêtes des clients.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"🚀 Démarré sur {HOST}:{PORT}")
        logging.info(f"🚀 Démarré sur {HOST}:{PORT}")
        while True:
            conn, _ = s.accept()
            threading.Thread(target=handle_client, args=(conn,), daemon=True).start()

if __name__ == '__main__':
    start_server()
