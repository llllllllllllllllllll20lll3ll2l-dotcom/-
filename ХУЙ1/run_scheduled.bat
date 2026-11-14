@echo off
REM Пример запуска автоматической очистки по расписанию (для Планировщика Windows).
REM 1) Настройте свои правила в example_rules.json
REM 2) Здесь: --execute реально удаляет, --yes без вопроса.
REM Для теста сначала запустите с --dry-run --list
cd /d "%~dp0"
python disk_cleaner.py --config example_rules.json --execute --yes >> clean_log.txt 2>&1
