# 🚀 Workflow quotidien - Projet FashionTrend

Ce guide résume les étapes à suivre chaque jour pour garder le projet propre, fonctionnel et synchronisé avec GitHub.

---

## 1. Travailler
- Modifier les **notebooks** dans `notebooks/`
- Éditer les **scripts Python** dans `src/`, `scripts/`, `api/`
- Ajouter des données brutes dans `data/raw/` (⚠️ pas de données sensibles ni trop lourdes)
- Enregistrer les modèles entraînés dans `models/` (⚠️ dossier ignoré par Git)

👉 **Astuce** : effacer les sorties des notebooks avant sauvegarde (sinon `nbstripout` le fera pour toi au commit).

---

## 2. Vérifier localement avant commit
Dans la racine du projet :

```bash
poetry run ruff check . --fix      # lint + corrections auto
poetry run black .                 # formatage du code
poetry run pytest -q               # exécuter les tests
poetry run python scan_secrets.py --skip-outputs --out secrets_report.md
```

---

## 3. Committer les changements
```bash
git status        # voir les fichiers modifiés
git add .         # ajouter les changements
git commit -m "Message clair (ex: Ajout fonction X dans src/features/)"
```

⚡ `pre-commit` s’exécute automatiquement ici :
- Nettoie les notebooks
- Vérifie la qualité du code (ruff, black)
- Bloque le commit si un problème est détecté

---

## 4. Envoyer sur GitHub
```bash
git push
```

La CI GitHub Actions démarre automatiquement :
- `ruff` (lint)
- `black --check` (format)
- `pytest` (tests unitaires)
- `scan_secrets.py` (fuite de secrets)

👉 Vérifie dans l’onglet **Actions** de GitHub :
- ✅ tout est vert : le dépôt est propre
- ❌ une étape échoue : corriger en local puis recommencer `git commit && git push`

---

## 5. Résumé express
1. **Coder**
2. **Vérifier localement** (ruff, black, pytest, scan secrets)
3. **Commit** (`git add . && git commit -m`)
4. **Push** (`git push`)
5. **Contrôler la CI GitHub**

---

✨ Avec ce workflow :
- Tu travailles sereinement sans crainte d’introduire du code cassé.
- Ton dépôt reste propre, reproductible et sécurisé.
- GitHub vérifie tout à chaque push.
