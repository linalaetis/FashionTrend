import os

from dotenv import load_dotenv
from huggingface_hub import whoami

# Charger les variables depuis .env
load_dotenv()

# Récupérer le token
token = os.getenv("HF_TOKEN")  # HUGGINGFACEHUB_API_TOKEN

if not token:
    print("❌ Aucun token trouvé dans .env")
else:
    print("✅ Token chargé :", token[:10] + "...")  # on n'affiche qu'une partie

    try:
        user_info = whoami(token=token)
        print("🎉 Connexion réussie à Hugging Face !")
        print("Utilisateur :", user_info.get("name"))
        print("Organisation :", user_info.get("orgs"))
    except Exception as e:
        print("❌ Erreur de connexion :", e)
