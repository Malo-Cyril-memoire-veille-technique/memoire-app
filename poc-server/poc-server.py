import socket
import threading
import os
import json
import uuid
import hashlib
import time

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
    Charger les données JSON à partir d'un fichier. Si le fichier n'existe pas, renvoyer un dictionnaire vide.
    Si le fichier est vide, renvoyer un dictionnaire vide.
    """
    with open(path, 'r') as f:
        return json.load(f)

def save_json(path, data):
    """
    Enregistrer les données JSON dans un fichier. Si le fichier n'existe pas, le créer.
    Si le fichier existe, écraser son contenu.
    """
    with open(path, 'w') as f:
        json.dump(data, f)

def handle_client(conn):
    """
    Gérer la connexion d'un client. Recevoir les données, traiter la requête et envoyer une réponse.
    Les actions possibles sont : register, login, logout, register_key, send_message, get_messages, get_key.
    """
    with conn:
        data = conn.recv(8192).decode()
        if not data:
            return
        try:
            req = json.loads(data)
        except json.JSONDecodeError:
            conn.sendall(json.dumps({"status": "error", "message": "invalid json"}).encode())
            return

        action = req.get("action")

        if action == "register":
            username = req.get("username")
            password = req.get("password")
            if not username or not password:
                conn.sendall(json.dumps({"status": "error", "message": "missing credentials"}).encode())
                return

            users = load_json(USERS_FILE)
            if username in users:
                conn.sendall(json.dumps({"status": "error", "message": "username already exists"}).encode())
                return

            hashed_pw = hashlib.sha256(password.encode()).hexdigest()
            users[username] = hashed_pw
            save_json(USERS_FILE, users)

            conn.sendall(json.dumps({"status": "ok", "message": "user created"}).encode())

        elif action == "login":
            username = req.get("username")
            password = req.get("password")
            if not username or not password:
                conn.sendall(json.dumps({"status": "error", "message": "missing credentials"}).encode())
                return

            users = load_json(USERS_FILE)
            hashed_input = hashlib.sha256(password.encode()).hexdigest()

            if username not in users:
                conn.sendall(json.dumps({"status": "error", "message": "unknown user"}).encode())
                return

            stored_hash = users[username]
            if hashed_input != stored_hash:
                conn.sendall(json.dumps({"status": "error", "message": "invalid password"}).encode())
                return

            sessions = load_json(SESSIONS_FILE)
            token = str(uuid.uuid4())
            sessions[token] = username
            save_json(SESSIONS_FILE, sessions)

            conn.sendall(json.dumps({"status": "ok", "token": token}).encode())

        elif action == "logout":
            token = req.get("token")
            sessions = load_json(SESSIONS_FILE)
            user = sessions.pop(token, None)
            if user:
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
            if not user or not public_key:
                conn.sendall(json.dumps({"status": "error", "message": "unauthorized or missing key"}).encode())
                return
            keys = load_json(KEYS_FILE)
            keys[user] = public_key
            save_json(KEYS_FILE, keys)
            conn.sendall(json.dumps({"status": "ok"}).encode())

        elif action == "send_message":
            token = req.get("token")
            to = req.get("to")
            message = req.get("message")

            sessions = load_json(SESSIONS_FILE)
            sender = sessions.get(token)

            if not sender or not to or not message:
                conn.sendall(json.dumps({"status": "error", "message": "missing or unauthorized"}).encode())
                return

            try:
                parsed_message = json.loads(message)
            except json.JSONDecodeError:
                conn.sendall(json.dumps({"status": "error", "message": "invalid message format"}).encode())
                return

            # Enregistrement du message pour le destinataire
            msgs = load_json(MESSAGES_FILE)
            msgs.setdefault(to, []).append(parsed_message)
            save_json(MESSAGES_FILE, msgs)

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
                conn.sendall(json.dumps({"status": "error", "message": "unauthorized"}).encode())
                return
            keys = load_json(KEYS_FILE)
            key = keys.get(target)
            if key:
                conn.sendall(json.dumps({"status": "ok", "key": key}).encode())
            else:
                conn.sendall(json.dumps({"status": "error", "message": "key not found"}).encode())

        else:
            conn.sendall(json.dumps({"status": "error", "message": "unknown action"}).encode())

def start_server():
    """
    Démarrer le serveur. Écouter les connexions entrantes et créer un thread pour chaque connexion.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[SERVER] Listening on {HOST}:{PORT}")
        while True:
            conn, _ = s.accept()
            threading.Thread(target=handle_client, args=(conn,), daemon=True).start()

if __name__ == '__main__':
    start_server()
