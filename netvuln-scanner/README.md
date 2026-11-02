# 🛡️ NetVuln-Scan — Scanner de Reconnaissance Réseau & Corrélation CVE

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://python.org)
[![Security](https://img.shields.io/badge/Cybersécurité-Reconnaissance-green?logo=kalilinux)](https://github.com/CalderaFourier-code)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Author](https://img.shields.io/badge/Auteur-Tohon%20Fourier-brightgreen)](https://github.com/CalderaFourier-code)

**NetVuln-Scan** est un outil en ligne de commande (CLI) multithreadé développé en Python, conçu pour auditer les services réseau exposés, extraire les bannières logicielles (*banner grabbing*) et corréler automatiquement les vulnérabilités **CVE** et scores **CVSS** connus.

Conçu avec la philosophie **zéro dépendance externe obligatoire** : le scanner fonctionne immédiatement avec la bibliothèque standard Python (`socket`, `ssl`, `urllib`, `concurrent.futures`, `json`).

---

## 🚀 Fonctionnalités Clés

- ⚡ **Scan de ports TCP multithreadé :** Balayage ultra-rapide avec pool d'exécution concurrent (`ThreadPoolExecutor`).
- 🕵️ **Banner Grabbing & Empreinte de service :** Sondage applicatif intelligent (SSH, FTP, SMTP, MySQL, sondes HTTP/HTTPS avec support SSL/TLS).
- 🧠 **Identification automatique des logiciels :** Détection d'Apache, Nginx, OpenSSH, vsftpd, ProFTPD, MySQL, IIS, etc.
- 🎯 **Corrélation de vulnérabilités CVE :**
  - Interrogation de l'API publique de **Shodan InternetDB** (détection des CVEs associées à l'IP sans clé API requise).
  - Interrogation de l'API **CIRCL CVE Search**.
  - Base de connaissances locale des failles critiques (RCE, Path Traversal, Backdoors).
- 📊 **Rapports d'audit professionnels :**
  - Affichage tabulaire couleur avec mise en évidence des sévérités CVSS (Critique, Élevé, Moyen).
  - Export **JSON** structuré (`--output`).
  - Export **HTML interactif** au thème Cyber/SOC (`--html`).
- 🧪 **Mode Démonstration intégré (`--demo`) :** Permet de tester le rendu et la détection instantanément sans cible réseau réelle.

---

## 📋 Prérequis & Installation

Aucune installation complexe de paquets n'est nécessaire. Clonez simplement le projet :

```bash
git clone https://github.com/CalderaFourier-code/netvuln-scanner.git
cd netvuln-scanner
```

Vérifiez que Python 3 est installé :
```bash
python --version
```

---

## 💻 Utilisation

### 1. Test instantané (Mode Démonstration)
Simule un audit sur une machine vulnérable avec génération automatique des rapports :
```bash
python scanner.py --demo
```

### 2. Scanner une cible avec les 30 ports les plus critiques
```bash
python scanner.py -t scanme.nmap.org
```

### 3. Scanner des ports spécifiques avec export HTML et JSON
```bash
python scanner.py -t 192.168.1.10 -p 21,22,80,443,8080 --html rapport.html --output audit.json
```

### 4. Scanner une plage de ports avec 100 threads
```bash
python scanner.py -t 10.0.0.5 -p 1-1000 --threads 100 --timeout 1.0
```

---

## 🖥️ Exemple de Sortie Terminal

```text
  _   _      _   __     __    _           ____                  
 | \ | | ___| |_ \ \   / /   | |_ __     / ___|  ___ __ _ _ __  
 |  \| |/ _ \ __| \ \ / /   | | '_ \ ____\___ \ / __/ _` | '_ \ 
 | |\  |  __/ |_   \ V /| |_| | | | |_____|__) | (_| (_| | | | |
 |_| \_|\___|\__|   \_/  \___/|_| |_|    |____/ \___\__,_|_| |_|
  [ Reconnaissance Réseau & Corrélation Automatisée de CVE ]
  Auteur : Tohon Fourier | GitHub: CalderaFourier-code | v1.0.0

[*] Cible résolue : 192.168.1.150 -> 192.168.1.150 (vulnerable-lab.local)
[*] Ports à auditer : 5 ports critiques | Threads: 10

  [+] Port 21    OUVERT -> FTP (220 vsFTPd 2.3.4)
  [+] Port 22    OUVERT -> SSH (SSH-2.0-OpenSSH_7.4p1 Debian-10)
  [+] Port 80    OUVERT -> HTTP (HTTP Server: Apache/2.4.49 (Unix))
  [+] Port 443   OUVERT -> HTTPS (HTTP Server: nginx/1.18.0)
  [+] Port 3306  OUVERT -> MySQL (5.7.34-MySQL Community Server)

===============================================================================================
RAPPORT D'AUDIT & CORRÉLATION DE VULNÉRABILITÉS
Cible : 192.168.1.150 (vulnerable-lab.local) | Durée : 0.85s | Ports Ouverts : 5
===============================================================================================
PORT     SERVICE      LOGICIEL DÉTECTÉ         VULNÉRABILITÉS / CVE                            
-----------------------------------------------------------------------------------------------
21/tcp   FTP          vsftpd 2.3.4             [CVE-2011-2523] (CVSS 9.8) Backdoor Command Execution
22/tcp   SSH          openssh 7.4              [CVE-2018-15473] (CVSS 5.3) User Enumeration vulnerabili
80/tcp   HTTP         apache 2.4.49            [CVE-2021-41773] (CVSS 9.8) Path Traversal & Remote Code
                                               [CVE-2021-42013] (CVSS 9.8) Path Traversal & RCE bypass
443/tcp  HTTPS        nginx 1.18.0             [CVE-2021-23017] (CVSS 7.7) 1-byte memory overwrite in r
3306/tcp MySQL        mysql 5.7.34             Aucune CVE critique connue
-----------------------------------------------------------------------------------------------
Synthèse : 5 service(s) actif(s) | 5 vulnérabilité(s) CVE associée(s)
===============================================================================================
```

---

## 📁 Architecture du Projet

```text
netvuln-scanner/
├── scanner.py          # Script principal du scanner CLI
├── README.md           # Documentation technique
├── rapport_demo.html   # Exemple de rapport HTML généré
└── rapport_demo.json   # Exemple d'exportation structurée
```

---

## ⚖️ Avertissement Légal / Disclaimer

Cet outil a été conçu à des fins éducatives et d'audit défensif uniquement. Il ne doit être utilisé que sur des systèmes et réseaux pour lesquels vous possédez une autorisation écrite expresse. L'auteur décline toute responsabilité quant à une utilisation malveillante ou non conforme aux lois en vigueur.

---

## 👤 Auteur

**Tohon Fourier**
- Spécialiste Cybersécurité Offensive & Défensive · DevSecOps
- GitHub : [@CalderaFourier-code](https://github.com/CalderaFourier-code)
- Email : [fouriertohon@gmail.com](mailto:fouriertohon@gmail.com)
