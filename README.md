# memoire-app

## Memo commandes docker :

### Terminal 1 (server)
```
# Sur powershell
docker-compose build server ; docker-compose run --rm -it server sh 
# Puis dans le shell avec un # pour executer le script (a voir si je peux pas l'automatiser)
python server.py

# ---------- Sinon linux
docker-compose build server && docker-compose run --rm -it server sh
# Puis pareil pour executer le script
python server.py
```

Si tout est ok c'est censé afficher : `[SERVER] Listening on 0.0.0.0:5000`

### Terminal 2 (client-a)
```
docker-compose run client_a
```

### Terminal 3 (client-b)
```
docker-compose run client_b
```
