# -*- coding: utf-8 -*-
"""
=============================================================================
  ATTACKGRAPH-AI — RECONNAISSANCE & ARCHITECTURE CORRELATION ENGINE
  DevSecOps Standards : Strict SSRF Protection, Safe Probing, Dynamic Mapping
  Auteur              : Tohon Fourier (CalderaFourier-code)
=============================================================================
"""

import ipaddress
import re
import socket
import ssl
import urllib.parse
import urllib.request
from .graph_engine import AttackNode, AttackEdge, AttackGraph


class SSRFProtector:
    """Bloque les accès aux adresses IP privées, localhost et métadonnées Cloud (RFC 1918 / Cloud Metadata)."""
    FORBIDDEN_NETWORKS = [
        ipaddress.ip_network("127.0.0.0/8"),      # Loopback
        ipaddress.ip_network("10.0.0.0/8"),       # Private Class A
        ipaddress.ip_network("172.16.0.0/12"),    # Private Class B
        ipaddress.ip_network("192.168.0.0/16"),   # Private Class C
        ipaddress.ip_network("169.254.169.254/32") # AWS/GCP/Azure Metadata
    ]

    @classmethod
    def is_safe(cls, hostname):
        try:
            ip_str = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip_str)
            for net in cls.FORBIDDEN_NETWORKS:
                if ip_obj in net:
                    return False, f"Adresse réseau privée ou métadonnées restreintes ({ip_str})"
            return True, ip_str
        except Exception as e:
            return False, f"Impossible de résoudre le domaine : {e}"


class ReconEngine:
    """Sonde la surface d'attaque externe et corrèle les vulnérabilités pour construire le graphe."""

    @staticmethod
    def build_custom_scenario(target_url, scenario_type="saas_jwt"):
        """Génère un graphe d'attaque d'entreprise complet et réaliste."""
        parsed = urllib.parse.urlparse(target_url if target_url.startswith("http") else f"https://{target_url}")
        domain = parsed.netloc or parsed.path or target_url

        graph = AttackGraph()

        if scenario_type == "saas_jwt":
            # Nœud 1 : Entrée Publique
            graph.add_node(AttackNode(
                node_id="N1_INTERNET",
                label="Attaquant Externe",
                category="entrypoint",
                asset_type="Internet",
                cvss=0.0,
                description="Point d'origine non authentifié situé sur Internet.",
                remediation="Filtrage WAF en bordure réseau."
            ))

            # Nœud 2 : Frontend & XSS
            graph.add_node(AttackNode(
                node_id="N2_FRONTEND",
                label=f"Frontend ({domain})",
                category="vulnerability",
                asset_type="Web",
                cvss=7.2,
                mitre_id="T1059.007",
                description="Formulaire de profil utilisateur vulnérable à une injection XSS stockée.",
                remediation="Activer une Content-Security-Policy (CSP) stricte et assainir les entrées utilisateur (DOMPurify)."
            ))

            # Nœud 3 : Session & Token JWT
            graph.add_node(AttackNode(
                node_id="N3_JWT_SESSION",
                label="Jeton de Session (JWT)",
                category="pivot",
                asset_type="Auth",
                cvss=8.1,
                mitre_id="T1539",
                description="Jeton JWT stocké sans protection dans le localStorage du navigateur.",
                remediation="Migrer le stockage du token vers un cookie sécurisé avec flags HttpOnly, Secure et SameSite=Strict."
            ))

            # Nœud 4 : API Gateway & BOLA
            graph.add_node(AttackNode(
                node_id="N4_API_GATEWAY",
                label="API Gateway (/api/v1)",
                category="vulnerability",
                asset_type="API",
                cvss=8.8,
                mitre_id="T1190",
                description="Contrôle d'accès défaillant au niveau de l'objet (BOLA / IDOR) sur la route d'administration.",
                remediation="Implémenter une vérification RBAC (Role-Based Access Control) côté serveur sur chaque ressource API."
            ))

            # Nœud 5 : Module d'Upload
            graph.add_node(AttackNode(
                node_id="N5_UPLOAD_SERVICE",
                label="Service Upload Fichiers",
                category="pivot",
                asset_type="Storage",
                cvss=9.0,
                mitre_id="T1105",
                description="Téléversement de fichiers sans validation stricte du type MIME réel ni renommage sécurisé.",
                remediation="Valider la signature binaire (magic bytes), renommer aléatoirement et stocker sur S3 sans droit d'exécution."
            ))

            # Nœud 6 : Console Administration
            graph.add_node(AttackNode(
                node_id="N6_ADMIN_DASHBOARD",
                label="Panneau SuperAdmin",
                category="pivot",
                asset_type="App",
                cvss=9.4,
                mitre_id="T1078",
                description="Accès aux fonctionnalités d'administration avancées et d'orchestration système.",
                remediation="Exiger une authentification multifacteur (MFA/FIDO2) obligatoire et restreindre par IP/VPN."
            ))

            # Nœud 7 : Joyau de la Couronne (BDD PostgreSQL)
            graph.add_node(AttackNode(
                node_id="N7_POSTGRES_DB",
                label="Base PostgreSQL (Crown Jewel)",
                category="crown_jewel",
                asset_type="Database",
                cvss=9.9,
                mitre_id="T1486",
                description="Base de données principale contenant 250 000 dossiers clients, coordonnées bancaires et hashs.",
                remediation="Chiffrer les données sensibles au repos (AES-256), segmenter le réseau et isoler la BDD dans un VPC privé."
            ))

            # Relations / Exploits (Edges)
            graph.add_edge(AttackEdge("N1_INTERNET", "N2_FRONTEND", "Injection de script malveillant (Stored XSS)", "Low", 0.9))
            graph.add_edge(AttackEdge("N2_FRONTEND", "N3_JWT_SESSION", "Exfiltration du localStorage vers serveur C2", "Low", 0.85))
            graph.add_edge(AttackEdge("N3_JWT_SESSION", "N4_API_GATEWAY", "Replay du token JWT sur endpoints API", "Medium", 0.8))
            graph.add_edge(AttackEdge("N4_API_GATEWAY", "N6_ADMIN_DASHBOARD", "Élévation de privilèges (BOLA sur /api/admin)", "Medium", 0.75))
            graph.add_edge(AttackEdge("N6_ADMIN_DASHBOARD", "N5_UPLOAD_SERVICE", "Appel de la fonction de téléversement média", "Low", 0.85))
            graph.add_edge(AttackEdge("N5_UPLOAD_SERVICE", "N7_POSTGRES_DB", "Exécution WebShell & lecture des identifiants DATABASE_URL", "High", 0.7))

        elif scenario_type == "cloud_ssrf":
            # Scénario Cloud AWS : SSRF to IAM to S3 Data Lake
            graph.add_node(AttackNode("N1_EXT", "Attaquant Internet", "entrypoint", "Internet", 0.0))
            graph.add_node(AttackNode("N2_WEB", f"Application Web ({domain})", "vulnerability", "Web", 8.6, "T1190", "SSRF sur le générateur de PDF externe.", "Valider et filtrer les URLs cibles avec une liste blanche stricte."))
            graph.add_node(AttackNode("N3_METADATA", "AWS Metadata (169.254.169.254)", "pivot", "Cloud", 9.1, "T1552.005", "Accès non filtré au service IMDSv1 de l'instance EC2.", "Activer IMDSv2 avec jeton de session obligatoire (Hop-Limit=1)."))
            graph.add_node(AttackNode("N4_IAM_ROLE", "Rôle IAM EC2 (Over-privileged)", "pivot", "Cloud", 8.9, "T1078.004", "Rôle IAM doté de permissions administrateur 's3:*'.", "Appliquer le principe de moindre privilège (POLP) sur les rôles IAM."))
            graph.add_node(AttackNode("N5_S3_LAKE", "S3 Data Lake (Crown Jewel)", "crown_jewel", "Storage", 9.8, "T1530", "Bucket S3 contenant les sauvegardes critiques et données clients.", "Chiffrement KMS, blocage de l'accès public et alerte CloudTrail GuardDuty."))

            graph.add_edge(AttackEdge("N1_EXT", "N2_WEB", "Envoi d'URL malveillante dans le champ export PDF", "Low", 0.9))
            graph.add_edge(AttackEdge("N2_WEB", "N3_METADATA", "Rebond SSRF vers http://169.254.169.254/latest/meta-data", "Medium", 0.85))
            graph.add_edge(AttackEdge("N3_METADATA", "N4_IAM_ROLE", "Vol des identifiants temporaires de sécurité (AWS_SECRET_ACCESS_KEY)", "Low", 0.95))
            graph.add_edge(AttackEdge("N4_IAM_ROLE", "N5_S3_LAKE", "Exfiltration massive des buckets S3 via AWS CLI", "Low", 0.9))

        elif scenario_type == "ecommerce_sqli":
            # Scénario E-Commerce : SQLi to Database
            graph.add_node(AttackNode("N1_WEB", "Visiteur Externe", "entrypoint", "Internet", 0.0))
            graph.add_node(AttackNode("N2_SEARCH", f"Catalogue ({domain})", "vulnerability", "Web", 8.9, "T1190", "Paramètre de recherche vulnérable à l'injection SQL aveugle.", "Utiliser des requêtes préparées (Prepared Statements / ORM)."))
            graph.add_node(AttackNode("N3_SESSION_CACHE", "Cache Redis de Session", "pivot", "Database", 7.5, "T1552", "Sessions administrateurs stockées en clair dans Redis sans auth.", "Exiger un mot de passe fort et activer le chiffrement TLS sur Redis."))
            graph.add_node(AttackNode("N4_CHECKOUT", "Passerelle Paiement & BDD (Crown Jewel)", "crown_jewel", "Database", 9.9, "T1005", "Cartes de crédit et commandes clients (PCI-DSS Impact).", "Isoler la passerelle de paiement (tokenisation Stripe/Adyen)."))

            graph.add_edge(AttackEdge("N1_WEB", "N2_SEARCH", "Saisie de payload SQL dans le filtre produit", "Low", 0.9))
            graph.add_edge(AttackEdge("N2_SEARCH", "N3_SESSION_CACHE", "Extraction des clés Redis et sessions administrateur", "Medium", 0.8))
            graph.add_edge(AttackEdge("N3_SESSION_CACHE", "N4_CHECKOUT", "Compromission de la table des transactions et cartes", "Low", 0.85))

        return graph
