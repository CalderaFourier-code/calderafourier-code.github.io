#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
  ATTACKGRAPH-AI — PRODUCTION-GRADE WEB SERVER & REST API
  Architecture DevSecOps : Non-root, Zero External Pip Dependencies, Secure Headers
  Auteur                 : Tohon Fourier (CalderaFourier-code)
  Version                : 1.0.0
=============================================================================
"""

import argparse
import http.server
import json
import mimetypes
import os
import sys
import urllib.parse
from core.graph_engine import AttackGraph
from core.recon_engine import ReconEngine, SSRFProtector
from core.ai_storyteller import AIStoryteller

# Assure la compatibilité UTF-8 sous Windows PowerShell / CMD
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


class AttackGraphAPIHandler(http.server.BaseHTTPRequestHandler):
    """Gestionnaire HTTP sécurisé avec API REST et headers de protection DevSecOps."""

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    STATIC_DIR = os.path.join(BASE_DIR, "static")

    def log_message(self, format, *args):
        # Format propre de log console
        sys.stdout.write(f"[{self.log_date_time_string()}] {self.command} {self.path} -> {args[1] if len(args) > 1 else ''}\n")
        sys.stdout.flush()

    def send_security_headers(self):
        """Injecte les en-têtes de sécurité recommandés par l'OWASP."""
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Server", "AttackGraph-Engine/1.0 (DevSecOps)")

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # 1. API: Liste des scénarios disponibles
        if path == "/api/scenarios":
            scenarios = [
                {
                    "id": "saas_jwt",
                    "title": "Application SaaS & API (XSS ➔ JWT ➔ BOLA ➔ BDD)",
                    "description": "Scénario classique d'une application web moderne : faille frontend permettant le vol de token de session et l'accès à la base de données via une API non restreinte."
                },
                {
                    "id": "cloud_ssrf",
                    "title": "Infrastructure Cloud AWS (SSRF ➔ IAM ➔ S3 Data Lake)",
                    "description": "Rebond depuis un générateur de PDF vers les métadonnées de l'instance EC2 (169.254.169.254), extraction des clés IAM et vidage du stockage cloud."
                },
                {
                    "id": "ecommerce_sqli",
                    "title": "Plateforme E-Commerce (SQLi ➔ Cache Redis ➔ Cartes Bancaires)",
                    "description": "Injection SQL sur le filtre de recherche permettant de voler les sessions administrateurs en cache et de compromettre la table des transactions."
                }
            ]
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_security_headers()
            self.end_headers()
            self.wfile.write(json.dumps(scenarios, ensure_ascii=False).encode("utf-8"))
            return

        # 2. Servir les fichiers statiques de l'application Web
        if path == "/" or path == "":
            path = "/index.html"

        # Protection contre Directory Traversal
        safe_path = os.path.normpath(path.lstrip("/"))
        file_path = os.path.join(self.STATIC_DIR, safe_path)

        if not file_path.startswith(self.STATIC_DIR) or not os.path.exists(file_path):
            self.send_error(404, "Fichier introuvable")
            return

        mime_type, _ = mimetypes.guess_type(file_path)
        if not mime_type:
            mime_type = "application/octet-stream"

        self.send_response(200)
        self.send_header("Content-Type", f"{mime_type}; charset=utf-8" if "text" in mime_type or "json" in mime_type else mime_type)
        self.send_security_headers()
        self.end_headers()

        with open(file_path, "rb") as f:
            self.wfile.write(f.read())

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/scan":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")

            try:
                data = json.loads(body)
                target_url = data.get("url", "https://entreprise.com").strip()
                scenario_type = data.get("scenario", "saas_jwt")

                # Validation & Sécurité SSRF
                if not target_url:
                    target_url = "https://entreprise.com"

                # Construction du graphe d'attaque
                graph = ReconEngine.build_custom_scenario(target_url, scenario_type=scenario_type)
                graph_data = graph.to_dict()

                # Génération de la narration offensive & recommandations
                narrative = AIStoryteller.generate_narrative(graph_data, target_url)

                response_payload = {
                    "target": target_url,
                    "scenario": scenario_type,
                    "graph": graph_data,
                    "narrative": narrative
                }

                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_security_headers()
                self.end_headers()
                self.wfile.write(json.dumps(response_payload, ensure_ascii=False).encode("utf-8"))

            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_security_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Erreur de traitement : {str(e)}"}).encode("utf-8"))
        else:
            self.send_error(404, "Endpoint non trouvé")


def run_server(host="127.0.0.1", port=8000):
    server_address = (host, port)
    httpd = http.server.HTTPServer(server_address, AttackGraphAPIHandler)
    print("\n" + "=" * 80)
    print("  ATTACKGRAPH-AI — SERVEUR WEB OPÉRATIONNEL")
    print(f"  URL : http://{host}:{port}")
    print("  Standards DevSecOps : En-têtes OWASP actifs, Protection SSRF, Zéro dépendance")
    print("=" * 80 + "\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Arrêt du serveur AttackGraph-AI.")
        httpd.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Serveur Web AttackGraph-AI")
    parser.add_argument("--host", default="127.0.0.1", help="Adresse IP d'écoute (Défaut: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port d'écoute (Défaut: 8000)")
    args = parser.parse_args()

    run_server(host=args.host, port=args.port)
