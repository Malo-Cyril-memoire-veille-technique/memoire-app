# client/client.py
import socket
import os
import json
import sys
import getpass
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

HOST = 'server'
PORT = 5000
KEY_FOLDER = 'keys'
os.makedirs(KEY_FOLDER, exist_ok=True)

session_token = None
username = ""
priv_key_path = ""
pub_key_path = ""

def send_request(data):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(json.dumps(data).encode())
        return s.recv(8192).decode()

def create_account():
    global username
    username = input("Créer un nom d'utilisateur : ").strip()
    password = getpass.getpass("Créer un mot de passe : ").strip()
    response = send_request({"action": "register", "username": username, "password": password})
    try:
        result = json.loads(response)
    except json.JSONDecodeError:
        print("[ERREUR] Réponse non valide du serveur :", response)
        return
    if result.get("status") == "ok":
        print("[INFO] Compte créé avec succès.")
    else:
        print("[ERREUR] Impossible de créer le compte :", result.get("message"))


def login():
    global username, session_token, priv_key_path, pub_key_path
    username = input("Nom d'utilisateur : ").strip()
    password = getpass.getpass("Mot de passe : ").strip()
    response = send_request({"action": "login", "username": username, "password": password})
    try:
        result = json.loads(response)
    except json.JSONDecodeError:
        print("[ERREUR] Réponse non valide du serveur :", response)
        return False
    if result.get("status") == "ok":
        session_token = result.get("token")
        priv_key_path = os.path.join(KEY_FOLDER, f"{username}_private.pem")
        pub_key_path = os.path.join(KEY_FOLDER, f"{username}_public.pem")
        load_keys()
        register_key()
        print("[INFO] Clé publique automatiquement enregistrée.")
        return True
    else:
        print("[ERREUR] Échec de la connexion :", result.get("message"))
        return False

def logout():
    global session_token
    send_request({"action": "logout", "token": session_token})
    session_token = None

def generate_keys():
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

def load_keys():
    if not os.path.exists(priv_key_path) or not os.path.exists(pub_key_path):
        generate_keys()
    with open(priv_key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(pub_key_path, 'rb') as f:
        public_key = f.read().decode()
    return private_key, public_key

def register_key():
    _, pub_key_str = load_keys()
    send_request({"action": "register_key", "token": session_token, "public_key": pub_key_str})

def get_key(target):
    response = send_request({"action": "get_key", "token": session_token, "target": target})
    result = json.loads(response)
    if result.get("status") == "ok":
        return result.get("key")
    return None

def send_message():
    to = input("Envoyer à : ")
    plaintext = input("Message : ")
    key_pem = get_key(to)
    if not key_pem:
        print("[ERROR] Clé du destinataire introuvable.")
        return
    public_key = serialization.load_pem_public_key(key_pem.encode())
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    send_request({"action": "send_message", "token": session_token, "to": to, "message": ciphertext.hex()})

def receive_messages():
    private_key, _ = load_keys()
    raw = send_request({"action": "get_messages", "token": session_token})
    result = json.loads(raw)
    if result.get("status") != "ok":
        print("[ERREUR]", result.get("message"))
        return
    messages = result.get("messages", [])
    for msg in messages:
        try:
            decrypted = private_key.decrypt(
                bytes.fromhex(msg),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            print("[RECU]", decrypted.decode())
        except Exception as e:
            print("[ERREUR] Impossible de déchiffrer :", str(e))

def main_menu():
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
                load_keys()
                user_menu()
        elif choice == '3':
            break
        else:
            print("[ERREUR] Choix invalide.")

def user_menu():
    while True:
        print(f"\n[CLIENT: {username}] Menu")
        print("1. Envoyer un message")
        print("2. Lire mes messages")
        print("3. Me déconnecter")
        choice = input("> ")
        if choice == '1':
            send_message()
        elif choice == '2':
            receive_messages()
        elif choice == '3':
            logout()
            print("[INFO] Déconnecté.")
            break
        else:
            print("[ERREUR] Choix invalide.")

if __name__ == '__main__':
    main_menu()
