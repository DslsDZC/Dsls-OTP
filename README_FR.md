# Dsls-OTP : Une solution de chiffrement réseau résistante aux quanta optimisée avec OTP

[English](README.md) / [简体中文](README_CN.md) / [日本語](README_JP.md) / Français / [Deutsch](README_DE.md)

![Static Badge](https://img.shields.io/badge/License_GNU_AFFERO-0?logo=gnu&color=8A2BE2)
<img src="https://img.shields.io/badge/python-3.10 ~ 3.13 -blue.svg" alt="python">

## ✨ Aperçu du projet

Dsls-OTP est une solution de chiffrement réseau résistante aux quanta optimisée avec le chiffrement par bloc unique (OTP). En combinant un mécanisme OTP optimisé avec des algorithmes de chiffrement modernes et des technologies résistantes aux quanta, il offre une protection exceptionnelle des données. Sa fonctionnalité de transmission réseau intégrée rend le transfert de fichiers sécurisé simple et efficace, adaptable à divers environnements réseau.

Que ce soit pour des appareils embarqués à ressources limitées ou des applications standard haute performance, Dsls-OTP propose des solutions flexibles.

---

## 🚀 Fonctionnalités principales

- **Sécurité de haut niveau** : Utilise des algorithmes de chiffrement de pointe comme AES-GCM et ChaCha20, combinés à Kyber et Dilithium pour une résistance quantique, garantissant une protection contre les menaces futures.
- **Support multi-mode** : Offre des modes léger et standard pour s'adapter aux exigences de performance de différents appareils.
- **Transmission efficace** : Les fonctionnalités de transmission réseau intégrées permettent un envoi et une réception de fichiers chiffrés rapides et sécurisés, améliorant considérablement l'efficacité opérationnelle.
- **Gestion intelligente des clés** : Inclut des outils de génération et de gestion de paires de clés ECC, simplifiant les opérations sur les clés tout en garantissant leur sécurité.
- **Large éventail d'applications** : De la protection des données personnelles au transfert de fichiers au niveau de l'entreprise, Dsls-OTP fournit une solution tout-en-un pour divers besoins.

---

## 📦 Structure des fichiers

```
Dsls-OTP/
├── python/
│   ├── dsls-otp.py       # Fichier principal du programme
│   ├── requirements.txt  # Liste des dépendances
├── README.md             # Documentation du projet
├── LICENSE               # Fichier de licence
```

---

## 📖 Utilisation

### 1. Chiffrer un fichier
```bash
python dsls-otp.py encrypt --input <chemin du fichier d'entrée> --output <chemin du fichier de sortie> --receiver-key <chemin du fichier de clé publique du destinataire> [--lightweight]
```

### 2. Déchiffrer un fichier
```bash
python dsls-otp.py decrypt --input <chemin du fichier d'entrée> --output <chemin du fichier de sortie> --private-key <chemin du fichier de clé privée> [--password <mot de passe de la clé privée>]
```

### 3. Générer une paire de clés
```bash
python dsls-otp.py keygen --private-key <chemin de sauvegarde de la clé privée> --public-key <chemin de sauvegarde de la clé publique> [--password <mot de passe de la clé privée>]
```

### 4. Envoyer un fichier chiffré via le réseau
```bash
python dsls-otp.py send --input <chemin du fichier d'entrée> --receiver-key <chemin du fichier de clé publique du destinataire> --target <IP:port cible> [--lightweight]
```

### 5. Recevoir et déchiffrer un fichier réseau
```bash
python dsls-otp.py receive --output <chemin du fichier de sortie> --private-key <chemin du fichier de clé privée> [--listen <adresse:port d'écoute>] [--password <mot de passe de la clé privée>]
```

---

## 🔧 Dépendances

- **Python** : Version 3.8 ou supérieure
- **Bibliothèques requises** : Installez-les avec la commande suivante :
  ```bash
  pip install -r requirements.txt
  ```

---

## 🛠️ Remarques

- Assurez-vous que la clé publique du destinataire et la clé privée de l'expéditeur sont stockées en toute sécurité.
- Lors de l'utilisation du mode léger, certains paramètres de sécurité peuvent être réduits pour améliorer les performances.

---

## 📜 Licence

Ce projet est open source sous licence GNU AFFERO. Consultez le fichier [LICENSE](LICENSE) pour plus de détails.

---

## ❤️ Communauté et support

Si vous avez des questions ou des suggestions, veuillez les soumettre via [Issues](https://github.com/DslsDZC/Dsls-OTP/issues) ou rejoindre nos discussions communautaires.

---

## ⭐ Comment contribuer

1. Forkez ce dépôt.
2. Créez votre branche (`git checkout -b feature/AmazingFeature`).
3. Commitez vos modifications (`git commit -m 'Add some AmazingFeature'`).
4. Poussez vers la branche (`git push origin feature/AmazingFeature`).
5. Ouvrez une Pull Request.

---

## 🌟 Remerciements

Merci à tous les développeurs qui ont contribué au code, à la documentation et aux suggestions pour ce projet !

<p align="center">
  <a href="https://github.com/DslsDZC/Dsls-OTP/graphs/contributors">
    <img src="https://contrib.rocks/image?repo=DslsDZC/Dsls-OTP" alt="Contributors">
  </a>
</p>
