@echo off
echo.
echo  =====================================================
echo   SecurPass v2.0 - Application Desktop Native
echo   Demarrage de l'application bureau (CustomTkinter)...
echo  =====================================================
echo.
cd /d "%~dp0"
echo [Setup] Verification des dependances Python...
pip install -r requirements.txt --quiet 2>nul
echo [Setup] Installation des navigateurs Playwright (Firefox)...
python -m playwright install firefox chromium 2>nul
echo.
python app.py
pause
