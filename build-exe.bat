@echo off
echo =====================================================
echo  SecurPass v2.0 - Build de l'Application Desktop (.exe)
echo =====================================================
echo.
cd /d "%~dp0"
echo Installation / Verification des dependances...
pip install pyinstaller customtkinter requests pyautogui pyperclip playwright 2>nul
echo Installation des navigateurs Playwright (Firefox + Chromium)...
python -m playwright install firefox chromium 2>nul

echo.
echo Compilation en executable Windows autonome (SecurPassDesktop.exe)...
pyinstaller --noconfirm --onedir --windowed --name "SecurPassDesktop" app.py

echo.
echo =====================================================
echo Build termine avec succes !
echo Retrouvez l'executable dans le dossier : dist\SecurPassDesktop\SecurPassDesktop.exe
echo =====================================================
pause
