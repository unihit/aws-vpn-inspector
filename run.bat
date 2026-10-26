@echo off
setlocal enabledelayedexpansion
title AWS Site-to-Site VPN Connectivity Inspector
echo ============================================================
echo   AWS Site-to-Site VPN Inspector - Local Agent Launcher
echo ============================================================
echo.

cd /d "%~dp0"

:: 1. Check if main.py exists. If not, auto-download repo from GitHub!
if not exist "main.py" (
    if exist "aws-vpn-inspector-main\main.py" (
        cd "aws-vpn-inspector-main"
    ) else (
        echo [*] 소스 코드를 찾을 수 없습니다. GitHub에서 최신 코드를 다운로드합니다...
        powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://github.com/unihit/aws-vpn-inspector/archive/refs/heads/main.zip' -OutFile 'aws-vpn-inspector.zip'; Expand-Archive -Path 'aws-vpn-inspector.zip' -DestinationPath '.' -Force; Remove-Item 'aws-vpn-inspector.zip' -Force"
        if exist "aws-vpn-inspector-main\main.py" (
            cd "aws-vpn-inspector-main"
        ) else (
            echo [!] 다운로드 실패. 인터넷 연결 또는 GitHub 저장소 접근 권한을 확인하세요.
            pause
            exit /b 1
        )
        echo [*] 다운로드 및 압축 해제 완료!
        echo.
    )
)

:: 2. Check Python installation
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [!] Python이 설치되어 있지 않거나 PATH 환경변수에 등록되지 않았습니다.
    echo     https://www.python.org 에서 Python 3.9 이상을 설치해 주세요.
    pause
    exit /b 1
)

:: 3. Check and install dependencies
echo [*] 필수 패키지 확인 중 (fastapi, uvicorn, boto3, jinja2)...
python -c "import fastapi, uvicorn, boto3, jinja2" >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [*] 필수 패키지 설치 진행 중 (최초 1회 실행)...
    pip install -r requirements.txt
)

:: 4. Launch server and auto-open browser
echo.
echo ============================================================
echo   로컬 웹 대시보드 시작: http://127.0.0.1:8085
echo   로컬 AWS 자격 증명(~/.aws)이 자동으로 감지됩니다.
echo ============================================================
echo.

start http://127.0.0.1:8085
python -m uvicorn main:app --host 127.0.0.1 --port 8085
pause
