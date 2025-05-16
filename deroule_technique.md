# Déroulé technique complet – Messagerie chiffrée avec interception (key escrow)

---

## 1. Architecture du système

L’architecture repose sur quatre types de conteneurs Docker communiquant sur un même réseau interne :

| Composant        | Rôle                                                                                                                             |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| **Client A / B** | Utilisateurs de la messagerie. Génèrent des paires de clés RSA. Interfacent avec le serveur via un protocole texte JSON          |
| **Serveur**      | Gère l’authentification, les sessions, les clés publiques et le stockage des messages                                            |
| **Autorité**     | Entité tierce disposant d’une backdoor via le champ `escrow`, permettant de déchiffrer les messages sans interaction utilisateur |

Les clients et le serveur échangent sur un port TCP (`5000`), avec des requêtes au format JSON.

---

## 2. Gestion des clés RSA

### Côté clients :

* Chaque client génère automatiquement **une paire de clés RSA 2048 bits** à la première connexion.
* La **clé privée** est stockée localement dans le conteneur (`keys/<user>_private.pem`).
* La **clé publique** est automatiquement envoyée au serveur via l’action `register_key`.

### Côté autorité :

* L’autorité dispose de **sa propre paire de clés RSA** (générée si absente au démarrage) dans `/app/keys/`.
* Elle est utilisée uniquement pour **déchiffrer le champ `escrow`** présent dans les messages.

---

## 3. Émission d’un message (côté client)

Quand un client veut envoyer un message, voici les étapes exactes :

### a. Construction du message clair

Le message contient :

```
FROM:<expéditeur>:<timestamp>:<contenu>
```

Exemple :

```
FROM:b:1747245867:coucou alice
```

### b. Signature numérique

Le message clair est **signé numériquement** avec la **clé privée** de l’expéditeur (RSA-PSS + SHA-256).

### c. Double chiffrement

Le message est :

1. **Chiffré pour le destinataire**, avec sa **clé publique** (RSA-OAEP + SHA-256).
2. **Chiffré pour l’autorité**, avec la **clé publique de l’autorité**, et stocké dans le champ `escrow`.

### d. Requête envoyée au serveur

Un objet JSON est envoyé via l’action `send_message`, contenant :

```json
{
  "message": "<ciphertext hex>",         // Pour le destinataire
  "signature": "<signature hex>",        // Signature du message clair
  "escrow": "<ciphertext hex>",          // Pour l'autorité
  "id": "<UUID>"                         // Identifiant unique
}
```

---

## 4. Traitement serveur

Le serveur TCP écoute sur le port 5000 et gère les actions suivantes :

* `register` : création de compte avec hachage du mot de passe (SHA-256).
* `login` : vérifie les identifiants et génère un token UUID.
* `register_key` : enregistre la clé publique d’un utilisateur.
* `get_key` : renvoie la clé publique d’un utilisateur cible.
* `send_message` : enregistre le message dans `messages.json`.

### Lors de `send_message` :

* Le serveur **ne lit pas le contenu** (il reste chiffré).
* Il journalise les champs `message`, `signature`, `escrow`, `id`, ainsi que l’expéditeur et le destinataire.
* Aucun déchiffrement n’a lieu ici : le serveur est "aveugle".

---

## 5. Récupération d’un message (côté client destinataire)

Le client effectue une action `get_messages`. Pour chaque message reçu :

1. Il **déchiffre le champ `message`** avec sa clé privée.
2. Il reconstruit le message clair et extrait :

   * l’expéditeur
   * le timestamp
   * le contenu
3. Il **récupère la clé publique** de l’expéditeur depuis le serveur (`get_key`) s’il ne l’a pas déjà.
4. Il **vérifie la signature numérique** :

   * Algorithme RSA-PSS avec SHA-256
   * Empreinte SHA-256 de la clé est logguée
5. Si la signature est valide et l’expéditeur reconnu : affichage + journalisation.

---

## 6. Interception autoritaire via key escrow

L’autorité est conçue pour analyser tous les messages, même s’ils sont chiffrés entre clients.

### Fonctionnement :

1. Elle lit en boucle `messages.json` et surveille les modifications par hachage (`SHA-256`).
2. Si des changements sont détectés :

   * Elle récupère tous les nouveaux messages contenant un champ `escrow`.
   * Elle les **déchiffre avec sa clé privée**.
3. Si le déchiffrement réussit, elle :

   * Extrait l’expéditeur, l’heure, le message clair.
   * Enregistre le message dans :

     * `logs/authority.log` (journal technique)
     * `intercepts/<sender>.log` (contenu texte lisible)

### Exemple de log :

```
Message intercepté de b à 2025-05-14 18:04:32
Contenu : coucou alice
ID : a9146955
Destinataire : a
```

---

## 7. Sécurité effective

### Ce qui est sécurisé :

* Le contenu est chiffré **client-side**.
* Le serveur n’a jamais accès au message en clair.
* Les signatures permettent de garantir l’**intégrité** et l’**authenticité**.

### Ce qui est compromis par design :

* Toute entité disposant de la **clé privée d’autorité** peut déchiffrer tous les messages via le `escrow`.
* Cette backdoor est invisible pour les utilisateurs.

---

### Conclusion technique

Cette architecture démontre qu’un système de messagerie peut paraître chiffré de bout en bout, tout en permettant à une autorité centrale de lire les échanges sans alerter les utilisateurs.
Le protocole met donc en évidence la limite entre sécurité perçue et sécurité réelle, dans un contexte où des mécanismes d’accès volontaire (ou imposé) peuvent être insérés dans l’infrastructure.