# 🕸️ AttackGraph-AI — Moteur de Graphes d'Attaque & Priorisation par Choke Points

[![Architecture](https://img.shields.io/badge/Architecture-DevSecOps%20Engineering-blue?logo=docker)](https://github.com/CalderaFourier-code)
[![Category](https://img.shields.io/badge/Security-Attack%20Path%20Management-red?logo=kalilinux)](https://github.com/CalderaFourier-code)
[![Graph Theory](https://img.shields.io/badge/Graph-DAG%20%26%20Shortest%20Path-purple)](https://github.com/CalderaFourier-code)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Author](https://img.shields.io/badge/Auteur-Tohon%20Fourier-brightgreen)](https://github.com/CalderaFourier-code)

> *"Personne ne veut lire un rapport de 300 vulnérabilités isolées. Tout le monde veut comprendre le chemin critique qui mène aux Joyaux de la Couronne."*

**AttackGraph-AI** est une plateforme d'**Attack Path Management (APM)** et de modélisation de menaces conçue selon les standards de l'ingénierie **DevSecOps senior**. Elle transforme la liste brute des failles de sécurité en un **graphe orienté acyclique (DAG)** interactif, calcule le plus court chemin critique vers les données sensibles (*Crown Jewels*), génère une narration exécutive pour le RSSI et identifie les **points d'étranglement (*Choke Points*)** permettant de neutraliser 100 % des chemins d'attaque avec un minimum d'efforts.

---

## 🌟 Principes d'Ingénierie & Fonctionnalités Clés

### 1. 🎯 Théorie des Graphes & Calcul du Chemin Critique
- **Modèle Formel ($G = (V, E)$)** : Chaque nœud $V$ représente un composant (Frontend, API, Auth, Stockage, BDD) ou une vulnérabilité. Chaque arête $E$ représente une condition d'exploit ou un pivot offensif.
- **Shortest Critical Path** : Algorithme de recherche de chemin pondéré identifiant la trajectoire la plus probable et la plus dévastatrice pour l'entreprise.

### 2. ⚡ Algorithme de Priorisation par Point d'Étranglement (*Choke Point Analysis*)
- Calcule la centralité des nœuds d'interconnexion.
- **Simulateur de Remédiation en Temps Réel** : En cliquant sur un point d'étranglement (ex: *sécurisation du token JWT* ou *contrôle BOLA sur l'API*), l'application démontre visuellement que toutes les étapes en aval (upload webshell, dump base de données) sont immédiatement coupées.

### 3. 🤖 Synthèse Exécutive pour le C-Level (CISO / RSSI)
- L'IA synthétise la chaîne d'attaque complexe en une **histoire d'infiltration claire et sans jargon**.
- Évaluation des impacts business quantifiés : perte financière estimée, sanctions réglementaires (RGPD / DORA / PCI-DSS) et CVSS maximal.

### 4. 🛡️ Standards DevSecOps & Sécurité Native
- **Protection Anti-SSRF Stricte** : Validation et blocage des adresses privées (RFC 1918) et des métadonnées Cloud (`169.254.169.254`).
- **En-têtes de Sécurité HTTP** : `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`.
- **Zéro Dépendance Pip Externe** : Fonctionne avec Python 3 standard (aucun package tiers vulnérable).
- **Conteneurisation Hardened** : Image Docker Alpine multi-stage exécutée avec un utilisateur non-privilégié (`USER 10001:10001`) et système de fichiers en lecture seule (`read_only: true`).

---

## 🚀 Démarrage Rapide

### Option A : Lancement en 1 Clic sous Windows
Double-cliquez simplement sur **`lancer_attackgraph.bat`** :
Le serveur démarre sur `http://localhost:8000` et ouvre automatiquement l'application dans votre navigateur.

### Option B : Lancement en ligne de commande (Python pur)
```bash
git clone https://github.com/CalderaFourier-code/attackgraph-ai.git
cd attackgraph-ai

python server.py --host 127.0.0.1 --port 8000
```
Ouvrez ensuite [http://localhost:8000](http://localhost:8000) dans votre navigateur.

### Option C : Déploiement Docker & DevSecOps
```bash
# Construction de l'image sécurisée non-root
docker build -t attackgraph-ai:latest .

# Lancement avec Docker Compose (limites CPU/RAM et lecture seule)
docker-compose up -d
```

---

## 📸 Scénarios d'Entreprise Intégrés

1. **Application SaaS Moderne & API** :
   `Internet ➔ XSS Stored ➔ Vol JWT LocalStorage ➔ BOLA sur API Gateway ➔ Upload WebShell ➔ Compromission BDD PostgreSQL`
2. **Infrastructure Cloud AWS & Microservices** :
   `Internet ➔ Faille SSRF sur générateur PDF ➔ Vol des clés IAM via 169.254.169.254 (IMDSv1) ➔ Exfiltration S3 Data Lake`
3. **Plateforme E-Commerce & Paiement** :
   `Visiteur Externe ➔ SQLi sur recherche catalogue ➔ Dump des sessions Redis ➔ Compromission des cartes de crédit (PCI-DSS)`

---

## 📁 Architecture Modulaire

```text
attackgraph-ai/
├── core/
│   ├── graph_engine.py      # Moteur de graphes orientés, Dijkstra & Choke Points
│   ├── recon_engine.py      # Moteur de reconnaissance & Protection Anti-SSRF
│   └── ai_storyteller.py    # Générateur de narration offensive & impact business
├── static/
│   ├── index.html           # Interface utilisateur interactive (Dashboard SOC)
│   ├── style.css            # Feuille de style Dark-Mode Cyberpunk / Threat Intel
│   └── app.js               # Contrôleur frontend, rendu SVG des arêtes & simulateur
├── server.py                # Serveur REST API avec en-têtes sécurisés OWASP
├── Dockerfile               # Conteneur Alpine hardened sans privilège root
├── docker-compose.yml       # Configuration de déploiement sécurisée
├── lancer_attackgraph.bat   # Lanceur 1-clic pour Windows
└── README.md                # Documentation technique complète
```

---

## 👤 Auteur

**Tohon Fourier**
- Spécialiste Cybersécurité Offensive & Défensive · DevSecOps
- GitHub : [@CalderaFourier-code](https://github.com/CalderaFourier-code)
- Email : [fouriertohon@gmail.com](mailto:fouriertohon@gmail.com)
