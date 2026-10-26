@echo off
echo Starting AWS Site-to-Site VPN Connectivity Inspector...
cd /d "%~dp0"
python -m uvicorn main:app --host 127.0.0.1 --port 8085 --reload
pause