#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
  NETVULN-SCAN — Scanner CLI de Reconnaissance & Corrélation CVE
  Auteur  : Tohon Fourier (CalderaFourier-code)
  Version : 1.0.0
  Usage   : python scanner.py --target <IP_OU_DOMAINE> [options]
=============================================================================
"""

import argparse
import concurrent.futures
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

# Assure la compatibilité UTF-8 sous Windows PowerShell / CMD
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# =============================================================================
# COULEURS ANSI & THÈME TERMINAL
# =============================================================================
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[92m"
    LIGHT_GREEN = "\033[38;5;82m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    YELLOW = "\033[93m"
    ORANGE = "\033[38;5;208m"
    RED = "\033[91m"
    DARK_RED = "\033[31m"
    MAGENTA = "\033[95m"
    GRAY = "\033[90m"
    BG_DARK = "\033[40m"


BANNER = f"""{Colors.GREEN}
  _   _      _   __     __    _           ____                  
 | \\ | | ___| |_ \\ \\   / /   | |_ __     / ___|  ___ __ _ _ __  
 |  \\| |/ _ \\ __| \\ \\ / /   | | '_ \\ ____\\___ \\ / __/ _` | '_ \\ 
 | |\\  |  __/ |_   \\ V /| |_| | | | |_____|__) | (_| (_| | | | |
 |_| \\_|\\___|\\__|   \\_/  \\___/|_| |_|    |____/ \\___\\__,_|_| |_|
  {Colors.CYAN}[ Reconnaissance Réseau & Corrélation Automatisée de CVE ]{Colors.RESET}
  {Colors.GRAY}Auteur : Tohon Fourier | GitHub: CalderaFourier-code | v1.0.0{Colors.RESET}
"""

# Top ports les plus courants pour scan rapide
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379,
    8000, 8080, 8443, 8888, 9000, 27017
]

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9000: "SonarQube/PHP",
    27017: "MongoDB"
}

# Base de connaissances locale des vulnérabilités critiques connues (fallback instantané)
KNOWN_VULNS_DB = {
    "apache": {
        "2.4.49": [
            {"id": "CVE-2021-41773", "cvss": 9.8, "severity": "CRITICAL", "desc": "Path Traversal & Remote Code Execution"},
            {"id": "CVE-2021-42013", "cvss": 9.8, "severity": "CRITICAL", "desc": "Path Traversal & RCE bypass"}
        ],
        "2.4.50": [
            {"id": "CVE-2021-42013", "cvss": 9.8, "severity": "CRITICAL", "desc": "Path Traversal and Remote Code Execution"}
        ],
        "2.2": [
            {"id": "CVE-2017-9798", "cvss": 7.5, "severity": "HIGH", "desc": "OptionsBleed memory disclosure vulnerability"}
        ]
    },
    "openssh": {
        "7.4": [
            {"id": "CVE-2018-15473", "cvss": 5.3, "severity": "MEDIUM", "desc": "User Enumeration vulnerability via malformed packets"}
        ],
        "8.5": [
            {"id": "CVE-2024-6387", "cvss": 8.1, "severity": "HIGH", "desc": "RegreSSHion: Remote Unauthenticated Code Execution"}
        ],
        "8.9": [
            {"id": "CVE-2023-38408", "cvss": 9.8, "severity": "CRITICAL", "desc": "PKCS#11 provider vulnerability in ssh-agent"}
        ]
    },
    "vsftpd": {
        "2.3.4": [
            {"id": "CVE-2011-2523", "cvss": 9.8, "severity": "CRITICAL", "desc": "Backdoor Command Execution (Smiley Face Backdoor)"}
        ]
    },
    "proftpd": {
        "1.3.5": [
            {"id": "CVE-2015-3306", "cvss": 10.0, "severity": "CRITICAL", "desc": "mod_copy arbitrary copy & RCE without authentication"}
        ]
    },
    "nginx": {
        "1.18.0": [
            {"id": "CVE-2021-23017", "cvss": 7.7, "severity": "HIGH", "desc": "1-byte memory overwrite in resolver component"}
        ]
    }
}


# =============================================================================
# MOTEUR DE SCAN & PROBING
# =============================================================================
class NetVulnScanner:
    def __init__(self, target, ports, timeout=1.5, threads=50, verbose=False):
        self.raw_target = target
        self.ports = ports
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.target_ip = None
        self.hostname = None
        self.results = []
        self.start_time = None
        self.end_time = None

    def resolve_target(self):
        """Résout l'adresse IP et le nom d'hôte de la cible."""
        try:
            self.target_ip = socket.gethostbyname(self.raw_target)
            try:
                self.hostname = socket.gethostbyaddr(self.target_ip)[0]
            except socket.herror:
                self.hostname = self.raw_target
            return True
        except socket.gaierror as e:
            print(f"{Colors.RED}[!] Erreur de résolution DNS pour '{self.raw_target}': {e}{Colors.RESET}")
            return False

    def check_port(self, port):
        """Tente une connexion TCP sur le port spécifié."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            result = sock.connect_ex((self.target_ip, port))
            if result == 0:
                service_name = PORT_SERVICES.get(port, "Inconnu")
                banner, software, version = self.grab_banner(sock, port)
                sock.close()
                return {
                    "port": port,
                    "state": "open",
                    "service": service_name,
                    "banner": banner,
                    "software": software,
                    "version": version,
                    "cves": []
                }
            sock.close()
            return None
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            return None

    def grab_banner(self, connected_sock, port):
        """Extrait la bannière de service via socket et protocole applicatif."""
        banner = ""
        software = None
        version = None

        # 1. Essai de lecture directe (ex: SSH, FTP, SMTP, MySQL)
        try:
            connected_sock.settimeout(1.2)
            data = connected_sock.recv(1024)
            if data:
                banner = data.decode("utf-8", errors="ignore").strip()
        except Exception:
            pass

        # 2. Si pas de bannière, envoi de sonde HTTP/HTTPS
        if not banner and port in [80, 443, 8000, 8080, 8443, 8888, 9000]:
            try:
                banner = self.probe_http(port)
            except Exception:
                pass

        # 3. Sonde générique si toujours vide
        if not banner:
            try:
                sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock2.settimeout(1.0)
                sock2.connect((self.target_ip, port))
                sock2.sendall(b"HELP\r\n\r\n")
                data = sock2.recv(512)
                banner = data.decode("utf-8", errors="ignore").strip()
                sock2.close()
            except Exception:
                pass

        # Nettoyage et extraction de software/version
        if banner:
            software, version = self.extract_software_version(banner, port)

        return banner[:120], software, version

    def probe_http(self, port):
        """Envoie une requête HEAD HTTP/HTTPS pour lire l'en-tête Server."""
        use_ssl = (port in [443, 8443])
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        try:
            sock.connect((self.target_ip, port))
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=self.hostname)

            req = f"HEAD / HTTP/1.1\r\nHost: {self.hostname}\r\nUser-Agent: NetVulnScan/1.0\r\nConnection: close\r\n\r\n"
            sock.sendall(req.encode())
            resp = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.close()

            # Extraction de l'en-tête Server
            match = re.search(r"Server:\s*([^\r\n]+)", resp, re.IGNORECASE)
            if match:
                return f"HTTP Server: {match.group(1).strip()}"
            first_line = resp.split("\r\n")[0] if resp else ""
            return first_line.strip()
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            return ""

    def extract_software_version(self, banner, port):
        """Parse la bannière pour extraire le nom du logiciel et sa version."""
        banner_clean = banner.replace("\r", " ").replace("\n", " ")

        patterns = [
            # OpenSSH_8.2p1
            (r"(OpenSSH)[_/ ]([0-9]+\.[0-9]+[a-zA-Z0-9_.-]*)", "openssh"),
            # Apache/2.4.49
            (r"(Apache)[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "apache"),
            # nginx/1.18.0
            (r"(nginx)[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "nginx"),
            # vsftpd 2.3.4
            (r"(vsftpd)[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "vsftpd"),
            # ProFTPD 1.3.5
            (r"(ProFTPD)[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "proftpd"),
            # Microsoft-IIS/10.0
            (r"(Microsoft-IIS)[/ ]([0-9]+\.[0-9]+)", "iis"),
            # MySQL 5.7.34
            (r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)[ -].*?(MariaDB|MySQL)", "mysql"),
            # Werkzeug / Python
            (r"(Werkzeug|Python)[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "python")
        ]

        for pat, key in patterns:
            m = re.search(pat, banner_clean, re.IGNORECASE)
            if m:
                if key == "mysql":
                    return m.group(2), m.group(1)
                return m.group(1), m.group(2)

        return None, None

    # =========================================================================
    # CORRÉLATION DE CVE (APIs & KNOWLEDGE BASE)
    # =========================================================================
    def correlate_cves(self, item):
        """Interroge la base locale et l'API InternetDB / CIRCL pour associer les CVEs."""
        cves = []
        software = (item.get("software") or "").lower()
        version = item.get("version") or ""

        # 1. Recherche dans la base de connaissances locale (Rapide & Garanti)
        for s_key, ver_dict in KNOWN_VULNS_DB.items():
            if s_key in software:
                for v_prefix, cve_list in ver_dict.items():
                    if version.startswith(v_prefix):
                        for c in cve_list:
                            if c not in cves:
                                cves.append(c)

        # 2. Interrogation de Shodan InternetDB API (Gratuit, sans clé API)
        try:
            url = f"https://internetdb.shodan.io/{self.target_ip}"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "NetVulnScan/1.0", "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    api_cves = data.get("vulns", [])
                    for cve_id in api_cves[:5]:  # Prendre les 5 premiers
                        if not any(c["id"] == cve_id for c in cves):
                            cves.append({
                                "id": cve_id,
                                "cvss": 7.5,
                                "severity": "HIGH",
                                "desc": f"Vulnérabilité référencée pour l'IP {self.target_ip}"
                            })
        except Exception:
            pass

        # 3. Interrogation CIRCL CVE Search API si logiciel et version identifiés
        if software and version and len(cves) < 3:
            try:
                circl_url = f"https://cve.circl.lu/api/search/{urllib.parse.quote(software)}"
                req = urllib.request.Request(
                    circl_url,
                    headers={"User-Agent": "NetVulnScan/1.0", "Accept": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        results = data.get("data", []) if isinstance(data, dict) else data
                        for item_cve in results[:3]:
                            cve_id = item_cve.get("id") or item_cve.get("cve", {}).get("id")
                            summary = item_cve.get("summary", "Vulnérabilité identifiée")
                            cvss = float(item_cve.get("cvss") or 5.0)
                            sev = "CRITICAL" if cvss >= 9.0 else "HIGH" if cvss >= 7.0 else "MEDIUM"
                            if cve_id and not any(c["id"] == cve_id for c in cves):
                                cves.append({
                                    "id": cve_id,
                                    "cvss": cvss,
                                    "severity": sev,
                                    "desc": (summary[:80] + "...") if len(summary) > 80 else summary
                                })
            except Exception:
                pass

        item["cves"] = cves
        return item

    def run(self):
        """Lance l'exécution complète du scanner."""
        self.start_time = datetime.now()
        print(f"\n{Colors.CYAN}[*] Cible résolue :{Colors.RESET} {self.raw_target} -> {Colors.BOLD}{self.target_ip}{Colors.RESET} ({self.hostname})")
        print(f"{Colors.CYAN}[*] Ports à scanner :{Colors.RESET} {len(self.ports)} ports | Threads: {self.threads} | Timeout: {self.timeout}s")
        print(f"{Colors.YELLOW}[*] Lancement du scan de détection en cours...{Colors.RESET}\n")

        open_ports = []
        scanned_count = 0
        total_ports = len(self.ports)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {executor.submit(self.check_port, p): p for p in self.ports}
            for future in concurrent.futures.as_completed(future_to_port):
                scanned_count += 1
                res = future.result()
                if res:
                    open_ports.append(res)
                    print(f"  {Colors.GREEN}[+] Port {res['port']:<5} OUVERT{Colors.RESET} -> {Colors.CYAN}{res['service']}{Colors.RESET} {Colors.GRAY}({res['banner'][:60] if res['banner'] else 'Aucune bannière'}){Colors.RESET}")
                else:
                    if self.verbose:
                        p = future_to_port[future]
                        print(f"  {Colors.GRAY}[-] Port {p:<5} fermé{Colors.RESET}")

        print(f"\n{Colors.CYAN}[*] Scan terminé.{Colors.RESET} {len(open_ports)} port(s) ouvert(s) identifié(s).")

        # Corrélation CVE
        if open_ports:
            print(f"{Colors.CYAN}[*] Corrélation des vulnérabilités CVE en cours...{Colors.RESET}")
            for item in open_ports:
                self.correlate_cves(item)

        self.results = sorted(open_ports, key=lambda x: x["port"])
        self.end_time = datetime.now()
        return self.results


# =============================================================================
# FORMATTAGE & AFFICHAGE DU RAPPORT
# =============================================================================
def print_report_table(results, target_ip, hostname, duration):
    """Affiche un tableau stylisé dans le terminal."""
    print("\n" + "=" * 95)
    print(f"{Colors.BOLD}{Colors.GREEN}RAPPORT D'AUDIT & CORRÉLATION DE VULNÉRABILITÉS{Colors.RESET}")
    print(f"Cible : {Colors.BOLD}{target_ip}{Colors.RESET} ({hostname}) | Durée : {duration:.2f}s | Ports Ouverts : {len(results)}")
    print("=" * 95)

    if not results:
        print(f"\n{Colors.YELLOW}[i] Aucun port ouvert détecté sur la cible dans la plage spécifiée.{Colors.RESET}\n")
        return

    # En-tête de tableau
    print(f"{Colors.BOLD}{'PORT':<8} {'SERVICE':<12} {'LOGICIEL DÉTECTÉ':<24} {'VULNÉRABILITÉS / CVE':<48}{Colors.RESET}")
    print("-" * 95)

    total_cves = 0

    for r in results:
        port_str = f"{r['port']}/tcp"
        service = r["service"]
        soft_ver = f"{r['software']} {r['version']}" if r.get("software") and r.get("version") else (r['banner'][:22] if r['banner'] else "N/A")

        cves = r.get("cves", [])
        total_cves += len(cves)

        if not cves:
            cve_str = f"{Colors.GREEN}Aucune CVE critique connue{Colors.RESET}"
            print(f"{Colors.CYAN}{port_str:<8}{Colors.RESET} {service:<12} {soft_ver:<24} {cve_str}")
        else:
            first = True
            for cve in cves:
                cve_id = cve["id"]
                cvss = cve.get("cvss", 0.0)
                sev = cve.get("severity", "INFO")

                sev_color = Colors.RED if sev == "CRITICAL" else Colors.ORANGE if sev == "HIGH" else Colors.YELLOW
                vuln_desc = f"{sev_color}{Colors.BOLD}[{cve_id}]{Colors.RESET} (CVSS {cvss}) {cve.get('desc', '')[:28]}"

                if first:
                    print(f"{Colors.CYAN}{port_str:<8}{Colors.RESET} {service:<12} {soft_ver:<24} {vuln_desc}")
                    first = False
                else:
                    print(f"{'':<8} {'':<12} {'':<24} {vuln_desc}")

    print("-" * 95)
    print(f"Synthèse : {Colors.BOLD}{len(results)} service(s) actif(s){Colors.RESET} | {Colors.RED if total_cves > 0 else Colors.GREEN}{total_cves} vulnérabilité(s) CVE associée(s){Colors.RESET}")
    print("=" * 95 + "\n")


# =============================================================================
# EXPORTS (JSON & HTML)
# =============================================================================
def export_json(results, target_ip, hostname, filepath):
    """Exporte le rapport complet au format JSON."""
    data = {
        "scan_metadata": {
            "scanner": "NetVuln-Scan",
            "author": "Tohon Fourier (CalderaFourier-code)",
            "target": target_ip,
            "hostname": hostname,
            "timestamp": datetime.now().isoformat(),
            "open_ports_count": len(results)
        },
        "findings": results
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"{Colors.GREEN}[✓] Rapport JSON exporté avec succès :{Colors.RESET} {filepath}")


def export_html(results, target_ip, hostname, duration, filepath):
    """Génère un rapport HTML cybersécurité aux couleurs Matrix / Cyber."""
    rows_html = ""
    for r in results:
        port = f"{r['port']}/tcp"
        service = r["service"]
        banner = r.get("banner") or "Non disponible"
        soft = f"{r['software']} {r['version']}" if r.get("software") else "Non catégorisé"

        cve_items = ""
        if r.get("cves"):
            for c in r["cves"]:
                badge_class = "crit" if c["severity"] == "CRITICAL" else "high" if c["severity"] == "HIGH" else "med"
                cve_items += f"""
                <div class="cve-badge {badge_class}">
                    <strong>{c['id']}</strong> (Score CVSS: {c['cvss']}) - {c.get('desc', '')}
                </div>"""
        else:
            cve_items = '<span class="cve-none">Aucune vulnérabilité immédiate répertoriée</span>'

        rows_html += f"""
        <tr>
            <td class="port-cell">{port}</td>
            <td class="service-cell">{service}</td>
            <td>{soft}<br><small class="banner-sub">{banner[:90]}</small></td>
            <td>{cve_items}</td>
        </tr>"""

    html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport d'Audit NetVuln-Scan - {target_ip}</title>
    <style>
        body {{
            background: #0a0e14;
            color: #dcdfe4;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 30px;
        }}
        .header {{
            border-bottom: 2px solid #00ff41;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        h1 {{
            color: #00ff41;
            margin: 0 0 10px 0;
            font-family: monospace;
            letter-spacing: 2px;
        }}
        .meta {{
            color: #5c6370;
            font-size: 13px;
        }}
        .meta strong {{ color: #00d4ff; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: #10151d;
            border-radius: 6px;
            overflow: hidden;
            border: 1px solid #1f2430;
        }}
        th {{
            background: #171d28;
            color: #00ff41;
            text-align: left;
            padding: 14px;
            font-size: 13px;
            border-bottom: 2px solid #00ff4133;
        }}
        td {{
            padding: 14px;
            border-bottom: 1px solid #1a202c;
            font-size: 13px;
            vertical-align: top;
        }}
        .port-cell {{ color: #00d4ff; font-weight: bold; font-family: monospace; }}
        .service-cell {{ color: #e5c07b; font-weight: 500; }}
        .banner-sub {{ color: #5c6370; font-family: monospace; font-size: 11px; }}
        .cve-badge {{
            padding: 6px 10px;
            border-radius: 4px;
            margin-bottom: 5px;
            font-size: 12px;
        }}
        .cve-badge.crit {{ background: rgba(255, 0, 64, 0.15); border: 1px solid #ff0040; color: #ff5370; }}
        .cve-badge.high {{ background: rgba(255, 140, 0, 0.15); border: 1px solid #ff8c00; color: #ffb454; }}
        .cve-badge.med  {{ background: rgba(255, 215, 0, 0.15); border: 1px solid #ffd700; color: #eed45e; }}
        .cve-none {{ color: #7f8c8d; font-style: italic; }}
        .footer {{
            margin-top: 40px;
            text-align: center;
            font-size: 12px;
            color: #5c6370;
            border-top: 1px solid #1f2430;
            padding-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>[+] RAPPORT NETVULN-SCAN</h1>
        <div class="meta">
            Cible : <strong>{target_ip}</strong> ({hostname}) | 
            Horodatage : <strong>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</strong> | 
            Durée d'audit : <strong>{duration:.2f}s</strong> | 
            Auditeur : <strong>Tohon Fourier</strong>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th style="width: 120px;">PORT</th>
                <th style="width: 140px;">SERVICE</th>
                <th style="width: 280px;">VERSION / BANNIÈRE</th>
                <th>VULNÉRABILITÉS & CORRÉLATION CVE</th>
            </tr>
        </thead>
        <tbody>
            {rows_html}
        </tbody>
    </table>

    <div class="footer">
        NetVuln-Scan v1.0.0 — Conçu par Tohon Fourier (CalderaFourier-code). Usage légitime et autorisé uniquement.
    </div>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"{Colors.GREEN}[✓] Rapport HTML interactif généré :{Colors.RESET} {filepath}")


def run_demo_mode(args):
    """Exécute une simulation complète pour tester l'affichage, la détection et les exports."""
    target_ip = "192.168.1.150"
    hostname = "vulnerable-lab.local"
    print(f"\n{Colors.YELLOW}[*] === MODE DÉMONSTRATION ACTIVÉ ==={Colors.RESET}")
    print(f"{Colors.CYAN}[*] Cible de laboratoire simulée :{Colors.RESET} {target_ip} ({hostname})")
    print(f"{Colors.CYAN}[*] Ports à auditer :{Colors.RESET} 5 ports critiques | Threads: 10\n")

    demo_ports = [
        {"port": 21, "service": "FTP", "banner": "220 vsFTPd 2.3.4", "software": "vsftpd", "version": "2.3.4"},
        {"port": 22, "service": "SSH", "banner": "SSH-2.0-OpenSSH_7.4p1 Debian-10", "software": "openssh", "version": "7.4"},
        {"port": 80, "service": "HTTP", "banner": "HTTP Server: Apache/2.4.49 (Unix)", "software": "apache", "version": "2.4.49"},
        {"port": 443, "service": "HTTPS", "banner": "HTTP Server: nginx/1.18.0", "software": "nginx", "version": "1.18.0"},
        {"port": 3306, "service": "MySQL", "banner": "5.7.34-MySQL Community Server", "software": "mysql", "version": "5.7.34"},
    ]

    for p in demo_ports:
        time.sleep(0.15)
        print(f"  {Colors.GREEN}[+] Port {p['port']:<5} OUVERT{Colors.RESET} -> {Colors.CYAN}{p['service']}{Colors.RESET} {Colors.GRAY}({p['banner']}){Colors.RESET}")

    print(f"\n{Colors.CYAN}[*] Corrélation des vulnérabilités CVE en cours...{Colors.RESET}")
    scanner = NetVulnScanner(target=target_ip, ports=[21, 22, 80, 443, 3306])
    scanner.target_ip = target_ip
    scanner.hostname = hostname

    for p in demo_ports:
        scanner.correlate_cves(p)

    duration = 0.85
    print_report_table(demo_ports, target_ip, hostname, duration)

    out_json = args.output or "rapport_demo.json"
    out_html = args.html or "rapport_demo.html"

    export_json(demo_ports, target_ip, hostname, out_json)
    export_html(demo_ports, target_ip, hostname, duration, out_html)
    print(f"\n{Colors.GREEN}[✓] Test de démonstration réussi sans aucune erreur !{Colors.RESET}\n")


# =============================================================================
# POINT D'ENTRÉE CLI (ARGPARSE)
# =============================================================================
def parse_ports(port_arg):
    """Convertit la chaîne d'arguments de ports en liste d'entiers."""
    if not port_arg:
        return TOP_PORTS
    ports = set()
    parts = port_arg.split(",")
    for p in parts:
        p = p.strip()
        if "-" in p:
            start, end = p.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(p))
    return sorted(list(ports))


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="NetVuln-Scan : Reconnaissance réseau, détection de bannières et corrélation CVE",
        epilog="Exemple : python scanner.py -t scanme.nmap.org --top-ports --html rapport.html"
    )
    parser.add_argument("-t", "--target", help="Adresse IP ou nom de domaine cible (ex: 127.0.0.1, scanme.nmap.org)")
    parser.add_argument("-p", "--ports", help="Ports spécifiques à scanner (ex: 80,443,8080 ou 1-1000). Par défaut: Top 30 ports.")
    parser.add_argument("--top-ports", action="store_true", help="Scanne les 30 ports les plus critiques (comportement par défaut)")
    parser.add_argument("--threads", type=int, default=50, help="Nombre de threads concurrents (Défaut: 50)")
    parser.add_argument("--timeout", type=float, default=1.5, help="Délai d'attente par socket en secondes (Défaut: 1.5s)")
    parser.add_argument("-o", "--output", help="Chemin du fichier pour export JSON (ex: audit.json)")
    parser.add_argument("--html", help="Chemin du fichier pour export du rapport HTML (ex: rapport.html)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Affiche les détails verbeux des ports fermés")
    parser.add_argument("--demo", action="store_true", help="Mode Démonstration : simule un audit complet avec détection de vulnérabilités critiques")

    args = parser.parse_args()

    if not args.target and not args.demo:
        parser.error("L'argument -t/--target est requis (ou utilisez --demo pour tester le scanner).")

    if args.demo:
        run_demo_mode(args)
        return

    ports_to_scan = parse_ports(args.ports)

    scanner = NetVulnScanner(
        target=args.target,
        ports=ports_to_scan,
        timeout=args.timeout,
        threads=args.threads,
        verbose=args.verbose
    )

    if not scanner.resolve_target():
        sys.exit(1)

    t_start = time.time()
    results = scanner.run()
    duration = time.time() - t_start

    # Affichage du rapport tabulaire
    print_report_table(results, scanner.target_ip, scanner.hostname, duration)

    # Exports optionnels
    if args.output:
        export_json(results, scanner.target_ip, scanner.hostname, args.output)

    if args.html:
        export_html(results, scanner.target_ip, scanner.hostname, duration, args.html)


if __name__ == "__main__":
    main()
