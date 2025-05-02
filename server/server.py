import socket
import threading
import os
import json
import uuid

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
    with open(path, 'r') as f:
        return json.load(f)

def save_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f)

def handle_client(conn):
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

        if action == "login":
            username = req.get("username")
            password = req.get("password")
            if not username or not password:
                conn.sendall(json.dumps({"status": "error", "message": "missing credentials"}).encode())
                return
            users = load_json(USERS_FILE)
            if username in users:
                if users[username] != password:
                    conn.sendall(json.dumps({"status": "error", "message": "invalid password"}).encode())
                    return
            else:
                users[username] = password
                save_json(USERS_FILE, users)
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
            msgs = load_json(MESSAGES_FILE)
            msgs.setdefault(to, []).append(message)
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
            user_msgs = msgs.pop(user, [])
            save_json(MESSAGES_FILE, msgs)
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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[SERVER] Listening on {HOST}:{PORT}")
        while True:
            conn, _ = s.accept()
            threading.Thread(target=handle_client, args=(conn,), daemon=True).start()

if __name__ == '__main__':
    start_server()
