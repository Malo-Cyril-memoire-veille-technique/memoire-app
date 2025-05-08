# memoire-app

## Memo commandes docker :

### Terminal 1 (server)
```sh
# Sur powershell
docker-compose build poc-server ; docker-compose run --rm -it poc-server

# ---------- Sinon linux
docker-compose build poc-server && docker-compose run --rm -it poc-server
```

Si tout est ok c'est censé afficher : `[SERVER] Listening on 0.0.0.0:5000`

### Terminal 2 (client-a)
```sh
docker-compose run client_a
```

### Terminal 3 (client-b)
```sh
docker-compose run client_b
```



### Arrêter / Supprimer les containers et images

```sh
# A CHANGER PARCE QUE PAS BON
# Containers 

# Images
# memoire-app-poc-server:latest
# memoire-app-client_a:latest
# memoire-app-client_b:latest

# Arrêt des conteneurs
docker stop poc-server client-a client-b

# Suppression des conteneurs
docker rm poc-server client-a client-b

# Suppression des images
docker rmi poc-server client-a client-b

# Suppression des volumes anonymes (optionnel)
docker volume prune -f

# Suppression du réseau personnalisé (remplace 'poc-net' si besoin)
docker network rm poc-net
```