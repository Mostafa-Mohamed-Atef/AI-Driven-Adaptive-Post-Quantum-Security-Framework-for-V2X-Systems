@echo off
echo ====================================
echo   V2X Security Architecture Setup
echo ====================================
echo.

REM Check if Docker is running
docker info > nul 2>&1
if errorlevel 1 (
    echo ERROR: Docker Desktop is not running!
    echo Please start Docker Desktop and try again.
    pause
    exit /b 1
)

echo 1. Building Docker images...
docker-compose build

echo.
echo 2. Starting V2X architecture...
docker-compose up -d

echo.
echo 3. Waiting for services to start...
timeout /t 10 /nobreak > nul

echo.
echo 4. Checking service status...
docker-compose ps

echo.
echo ====================================
echo   SERVICES READY
echo ====================================
echo Root CA:        http://localhost:5001
echo PCA:            http://localhost:5002
echo Registration:   http://localhost:5003
echo Misbehavior:    http://localhost:5004
echo Dashboard:      http://localhost:8080
echo.
echo Press any key to stop services...
pause > nul

echo.
echo 5. Stopping services...
docker-compose down