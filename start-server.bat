@echo off
echo.
echo  =====================================================
echo   SecurPass - Gestionnaire de Mots de Passe
echo   Demarrage du serveur...
echo  =====================================================
echo.
echo  Ouvrez votre navigateur et accedez a :
echo  http://localhost:5000
echo.
echo  Identifiants de demonstration (LDAP_MOCK=true) :
echo    - admin / Admin@2026!
echo    - administrateur / Admin@2026!
echo    - user  / User@2026!
echo.
echo  Le SSO automatique detecte le compte Windows actuel.
echo  Aucune configuration SSO_USERNAME_MAP n'est necessaire.
echo.
echo  Appuyez sur CTRL+C pour arreter le serveur.
echo.
cd /d "%~dp0backend"
node src\server.js