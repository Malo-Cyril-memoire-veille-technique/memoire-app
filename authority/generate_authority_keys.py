from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os
import logging

KEY_DIR = "/app/keys"
PRIVATE_KEY_FILE = os.path.join(KEY_DIR, "authority_private.pem")
PUBLIC_KEY_FILE = os.path.join(KEY_DIR, "authority_public.pem")
LOG_FILE = "/app/logs/authority.log"  # log fusionné avec l'autorité

os.makedirs("/app/logs", exist_ok=True)
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def generate_keys_if_needed():
    """
    Générer les clés de l'autorité si elles n'existent pas déjà.
    """
    os.makedirs(KEY_DIR, exist_ok=True)

    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        logging.info("Clés de l'autorité déjà présentes. Aucune action nécessaire.")
        return

    try:
        logging.info("Génération des clés de l'autorité...")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        public_key = private_key.public_key()
        with open(PUBLIC_KEY_FILE, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        logging.info("Clés de l'autorité générées avec succès.")
    except Exception as e:
        logging.error(f"Échec lors de la génération des clés : {e}")

if __name__ == "__main__":
    logging.info("Lancement du script de génération de clés de l'autorité")
    generate_keys_if_needed()
