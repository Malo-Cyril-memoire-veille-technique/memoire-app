import os
import json
import time
from datetime import datetime
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from generate_authority_keys import generate_keys_if_needed

# Génération de clés si absentes
generate_keys_if_needed()

KEY_PATH = "/app/keys/authority_private.pem"
DATA_FOLDER = "/app/intercepts"
SEEN_IDS_FILE = "/app/data/state/seen_ids.json"
LAST_HASH_FILE = "/app/data/state/last_seen.hash"
MESSAGES_FILE = "/app/data/messages.json"

# Créer les dossiers nécessaires uniquement en écriture locale
os.makedirs("/app/data/state", exist_ok=True)
os.makedirs(DATA_FOLDER, exist_ok=True)

# Charger la clé privée
try:
    with open(KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
except FileNotFoundError:
    print("[ERREUR] Clé privée manquante.", flush=True)
    exit(1)

def load_seen_ids():
    """
    Charger les IDs vus à partir du fichier. Si le fichier n'existe pas ou est vide, renvoyer un ensemble vide.
    """
    try:
        with open(SEEN_IDS_FILE, "r") as f:
            return set(json.load(f))
    except:
        return set()

def save_seen_ids(ids):
    """
    Enregistrer les IDs vus dans le fichier. Si le fichier n'existe pas, le créer.
    Si le fichier existe, écraser son contenu.
    """
    with open(SEEN_IDS_FILE, "w") as f:
        json.dump(list(ids), f)

def load_messages():
    """
    Charger les messages à partir du fichier. Si le fichier n'existe pas ou est vide, renvoyer un dictionnaire vide.
    """
    try:
        with open(MESSAGES_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def compute_hash(data):
    """
    Calculer le hash SHA-256 d'un dictionnaire. Le dictionnaire est trié pour garantir la cohérence du hash.
    """
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

def save_intercept(sender, timestamp, message):
    """
    Enregistrer un message intercepté dans un fichier. Le nom du fichier est basé sur l'expéditeur.
    Le message est horodaté et formaté pour une lecture facile.
    """
    filename = os.path.join(DATA_FOLDER, f"{sender}.log")
    with open(filename, "a") as f:
        f.write(f"[{datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")

def run_monitor():
    """
    Surveiller les messages en boucle. Si un nouveau message est détecté, le déchiffrer et l'enregistrer.
    Le hash des messages est utilisé pour détecter les changements. Les IDs des messages vus sont enregistrés pour éviter les doublons.
    """
    last_seen_hash = ""
    if os.path.exists(LAST_HASH_FILE):
        with open(LAST_HASH_FILE, "r") as f:
            last_seen_hash = f.read().strip()

    seen_ids = load_seen_ids()

    while True:
        all_messages = load_messages()
        new_hash = compute_hash(all_messages)

        if new_hash != last_seen_hash:
            last_seen_hash = new_hash
            with open(LAST_HASH_FILE, "w") as f:
                f.write(new_hash)

            for recipient, messages in all_messages.items():
                for msg in messages:
                    if "escrow" not in msg:
                        continue
                    msg_id = msg.get("id")
                    if not msg_id or msg_id in seen_ids:
                        continue

                    try:
                        encrypted = bytes.fromhex(msg["escrow"])
                        decrypted = private_key.decrypt(
                            encrypted,
                            padding.OAEP(
                                mgf=padding.MGF1(hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        ).decode()

                        if decrypted.startswith("FROM:"):
                            parts = decrypted.split(":", 3)
                            sender = parts[1].strip()
                            timestamp = int(parts[2].strip())
                            text = parts[3].strip()

                            print(f"[INTERCEPTÉ] {sender}: {text}", flush=True)
                            save_intercept(sender, timestamp, text)
                            seen_ids.add(msg_id)
                            save_seen_ids(seen_ids)

                    except Exception as e:
                        print(f"[ERREUR] Déchiffrement échoué : {e}", flush=True)
                        continue
        time.sleep(3)

if __name__ == "__main__":
    print("[AUTORITÉ] Surveillance des messages démarrée...", flush=True)
    run_monitor()
