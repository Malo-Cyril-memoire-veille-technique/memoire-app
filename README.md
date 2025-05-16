# memoire-app

## Memo commandes docker :

### Terminal 1 (server)
```sh
# Sur powershell
docker-compose build poc-server ; docker-compose run --rm -it poc-server

# Sinon linux
docker-compose build poc-server && docker-compose run --rm -it poc-server
```

Si tout est ok c'est censé afficher : `[SERVER] Listening on 0.0.0.0:5000`

### Terminal 2 (authority)
```sh
# Sur windows
docker-compose build authority ; docker-compose run --rm -it authority

# Sinon linux
docker-compose build authority && docker-compose run --rm -it authority
```

### Terminal 3 (client-a)
```sh
docker-compose run client_a
```

### Terminal 4 (client-b)
```sh
docker-compose run client_b
```