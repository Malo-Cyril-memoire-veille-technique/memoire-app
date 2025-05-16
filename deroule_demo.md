# Déroulé de la démonstration – Messagerie chiffrée avec key escrow

---

## Objectif de la démo

Montrer qu’une messagerie qui utilise du chiffrement et des signatures numériques peut tout de même être interceptée par une autorité via une backdoor intégrée au protocole (`escrow`).

---

## Étapes de la démonstration

---

### 1. Lancement du **serveur**

**Terminal 1**

```bash
docker-compose build poc-server && docker-compose run --rm -it poc-server
```

* Affiche : `[SERVER] Listening on 0.0.0.0:5000`
* Initialise les fichiers `users.json`, `sessions.json`, `public_keys.json`, `messages.json`
* Tous les échanges passent par ce point central
* Il journalise chaque requête importante dans `logs/server.log`

---

### 2. Lancement de l’**autorité**

**Terminal 2**

```bash
docker-compose build authority && docker-compose run --rm -it authority
```

* Affiche : `[AUTORITÉ] Surveillance des messages démarrée...`
* Si les clés n’existent pas encore, elles sont générées dans `/app/keys`
* Le script entre en boucle et surveille toute modification dans `messages.json`
* Lorsqu’un message contenant `escrow` est détecté, il est automatiquement déchiffré avec la clé privée
* L’autorité journalise :

  * L’ID du message
  * L’expéditeur
  * Le contenu clair intercepté
  * Le destinataire
  * Et conserve une trace textuelle dans `intercepts/<sender>.log`

---

### 3. Lancement du **client A**

**Terminal 3**

```bash
docker-compose run client_a
```

* A crée un compte (si ce n’est pas déjà fait)
* Il se connecte et enregistre automatiquement sa clé publique
* Il peut initier ou répondre à une conversation
* Il affiche une interface ligne de commande type :

  ```
  --- MENU PRINCIPAL ---
  1. Créer un compte
  2. Se connecter
  3. Quitter
  ```

---

### 4. Lancement du **client B**

**Terminal 4**

```bash
docker-compose run client_b
```

* Même processus que client A
* B crée ou utilise son compte
* Après connexion, il lance une conversation vers A :

  ```
  [Conversation avec a]
  b > salut alice
  ```
* Ce message est automatiquement :

  * Signé
  * Chiffré pour A
  * Chiffré pour l’autorité (champ `escrow`)
  * Envoyé au serveur avec un identifiant unique

---

### 5. Observation de l’interception

**Dans le terminal de l’autorité**, quelques secondes après l’envoi :

```
[INTERCEPTÉ] b: salut alice
📥 Message intercepté de b à 2025-05-14 18:04:32
🔓 Contenu déchiffré brut : FROM:b:1747245872:salut alice
📝 Contenu : salut alice
🆔 ID du message : a9146955
👤 Destinataire : a
```

**Dans `logs/authority.log`**, toutes ces infos sont enregistrées.

---

### 6. Vérification côté client

Client A voit apparaître le message reçu en clair :

```
[18:04] b : salut alice
a >
```

Et dans `logs/client-a.log` :

```
📥 Nouveau message reçu de b
🔓 Déchiffrement obtenu : FROM:b:...
📥 Signature vérifiée avec succès
```

---

### 7. Vérification des logs

* `server.log` montre que le message a bien été stocké
* `authority.log` montre que l’interception a bien eu lieu
* `client-b.log` montre que le message a été signé, chiffré, envoyé avec escrow

---

## Conclusion de la démo

Tu peux conclure oralement en expliquant :

* Que malgré un chiffrement asymétrique entre utilisateurs, le champ `escrow` permet à une autorité tierce de lire tous les échanges
* Que cette démonstration illustre les risques liés aux backdoors intégrées dès la conception, même dans un système techniquement "chiffré de bout en bout"
* Que le système est transparent pour les utilisateurs : ni A ni B ne savent que leurs échanges sont interceptés