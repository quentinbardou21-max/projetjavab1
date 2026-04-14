# Projet Java Logs

## Objectif
Analyser des fichiers de logs Apache et afficher des rapports.

## Java
Pour lancer l'analyse en console :
1. `javac src/*.java src/detectors/*.java`
2. `java -cp src Main`
3. Optionnel : préciser un fichier de logs, par exemple `java -cp src Main ressources/access_log_clean.txt`

## Web
Le front est statique, donc il faut le servir en local avant de l’ouvrir dans le navigateur :
1. Ouvrir un terminal dans la racine du projet.
2. Lancer `python3 -m http.server 8000 --directory web`.
3. Ouvrir `http://localhost:8000` dans le navigateur.
4. Choisir un fichier de logs Apache `.txt`.
5. Optionnel : charger aussi un fichier de White list, avec des IPs (une ou plusieurs par ligne).
6. Cliquer sur `Analyser` pour afficher le dashboard, les tableaux de statistiques, la synthèse de sécurité, les règles de blocage et la détection de menaces.

Les utilitaires Java historiques ont été déplacés dans `legacy/` pour garder la racine propre.
