@echo off
rem Builds dist\UnoKeyVault.exe. Needs Python 3 from python.org (with the "py" launcher).
cd /d "%~dp0"
py -3 -m pip install --user -r requirements.txt pyinstaller || goto :error
py -3 -m PyInstaller --noconfirm --onefile --windowed --name UnoKeyVault unokey_app.py || goto :error
echo.
echo Done: %~dp0dist\UnoKeyVault.exe
goto :eof

:error
echo Build failed.
exit /b 1
