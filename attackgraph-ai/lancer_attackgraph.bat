@echo off
title AttackGraph-AI — Moteur de Graphes d'Attaque & Priorisation
color 0b
echo ====================================================================
echo   ATTACKGRAPH-AI — Lancement du Serveur Web DevSecOps...
echo   Auteur : Tohon Fourier (CalderaFourier-code)
echo ====================================================================
echo.

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERREUR] Python n'est pas installe ou pas dans le PATH.
    pause
    exit /b
)

echo [OK] Demarrage du serveur sur http://localhost:8000...
echo Votre navigateur va s'ouvrir automatiquement.
echo.

start "" http://localhost:8000
python server.py --host 127.0.0.1 --port 8000
pause
