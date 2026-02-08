@echo off
setlocal

if "%VIRTUAL_ENV%"=="" (
  echo [INFO] Nincs aktiv virtual environment. Javasolt: python -m venv .venv && .venv\Scripts\activate
)

python -m pip install --upgrade pip
python -m pip install pyinstaller

pyinstaller --noconfirm --onefile --windowed --name "DeveloperToolKit" app.py

echo.
echo Kesz: dist\DeveloperToolKit.exe
endlocal
