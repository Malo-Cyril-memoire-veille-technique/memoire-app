# Liste des noms à supprimer
$names = @("poc-server", "poc-client-a", "poc-client-b")

# Stopper et supprimer les conteneurs
foreach ($name in $names) {
    Write-Host "Arrêt de $name..."
    docker stop $name -ErrorAction SilentlyContinue | Out-Null
    Write-Host "Suppression de $name..."
    docker rm $name -ErrorAction SilentlyContinue | Out-Null
}

# Supprimer les images
foreach ($name in $names) {
    Write-Host "Suppression de l'image $name..."
    docker rmi $name -ErrorAction SilentlyContinue | Out-Null
}

Write-Host "Nettoyage terminé."