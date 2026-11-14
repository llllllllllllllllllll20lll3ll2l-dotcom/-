@echo off
REM Запуск графического интерфейса Disk Cleaner
cd /d "%~dp0"
python disk_cleaner.py
if errorlevel 1 pause
