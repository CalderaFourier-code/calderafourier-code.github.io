# =============================================================================
# ATTACKGRAPH-AI — PRODUCTION HARDENED DOCKERFILE
# Security Standards: Non-Root Execution, Minimal Alpine Base, Zero Pip Packages
# =============================================================================

FROM python:3.12-alpine

# Métadonnées de sécurité OCI
LABEL maintainer="Tohon Fourier <fouriertohon@gmail.com>"
LABEL org.opencontainers.image.title="AttackGraph-AI"
LABEL org.opencontainers.image.description="Moteur de Graphes d'Attaque & Priorisation Choke Points"
LABEL org.opencontainers.image.source="https://github.com/CalderaFourier-code/attackgraph-ai"

# Création d'un utilisateur et groupe non-root dédié (Security Best Practice)
RUN addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S appuser -G appgroup

WORKDIR /app

# Copie des sources avec permissions strictes
COPY --chown=appuser:appgroup . /app

# Bascule vers l'utilisateur non-privilégié
USER 10001:10001

# Port d'écoute du serveur DevSecOps
EXPOSE 8000

# Healthcheck de disponibilité
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/').read()" || exit 1

# Démarrage du serveur API & Web
ENTRYPOINT ["python", "server.py", "--host", "0.0.0.0", "--port", "8000"]
