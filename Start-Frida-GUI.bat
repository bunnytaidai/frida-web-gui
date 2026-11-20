@echo off
chcp 65001 >nul
title Frida JS Web Console - Local PC GUI
cd /d "%~dp0"
echo [Frida Web GUI] Dang khoi dong may chu tai http://127.0.0.1:3456 ...
start "" "http://127.0.0.1:3456"
node src/server.mjs
pause

