@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
title Typora Activation

where node >nul 2>nul
if errorlevel 1 (
    echo [X] Node.js not found: https://nodejs.org/
    pause
    exit /b 1
)

node "%~dp0typora-crack.js" %*

echo.
echo Done. Open Typora -^> Help -^> My License to check status.
pause
