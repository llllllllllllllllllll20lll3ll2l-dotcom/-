@echo off
REM ============================================================
REM  Disk Cleaner - one-shot installer
REM  Installs Python (if missing) + project dependencies.
REM  Safe to run twice: it skips steps that are already done.
REM  ASCII-only on purpose to avoid console codepage issues.
REM ============================================================
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul 2>&1

title Disk Cleaner - Installer

set "ROOT=%~dp0"
set "REQ=%ROOT%requirements.txt"
set "PYVER=3.12.7"
set "PYURL=https://www.python.org/ftp/python/%PYVER%/python-%PYVER%-amd64.exe"
set "INSTALLER=%TEMP%\python-%PYVER%-amd64.exe"
set "PY="

echo.
echo ============================================================
echo   Disk Cleaner installer
echo ============================================================
echo.

REM ---------- [1/4] Detect a usable Python (3.8+) ----------
echo [1/4] Looking for Python 3.8+ ...

REM Try "py" launcher first (installed by python.org installer).
py -3 -c "import sys;sys.exit(0 if sys.version_info>=(3,8) else 1)" >nul 2>&1
if not errorlevel 1 (
    set "PY=py -3"
    goto :found_python
)

REM Try "python" on PATH.
python -c "import sys;sys.exit(0 if sys.version_info>=(3,8) else 1)" >nul 2>&1
if not errorlevel 1 (
    set "PY=python"
    goto :found_python
)

REM Try common install locations directly.
for %%P in (
    "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    "%ProgramFiles%\Python313\python.exe"
    "%ProgramFiles%\Python312\python.exe"
    "%ProgramFiles%\Python311\python.exe"
) do (
    if not defined PY if exist %%P (
        "%%~P" -c "import sys;sys.exit(0 if sys.version_info>=(3,8) else 1)" >nul 2>&1
        if not errorlevel 1 set "PY=%%~P"
    )
)
if defined PY goto :found_python

echo     Python 3.8+ not found. Will install it.
echo.

REM ---------- [2/4] Install Python ----------
echo [2/4] Installing Python %PYVER% ...

where winget >nul 2>&1
if not errorlevel 1 (
    echo     Using winget ...
    winget install -e --id Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
    goto :post_install
)

echo     winget not available. Downloading installer from python.org ...
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '%PYURL%' -OutFile '%INSTALLER%' -UseBasicParsing } catch { Write-Host 'DOWNLOAD FAILED:' $_.Exception.Message; exit 1 }"
if errorlevel 1 goto :install_failed
if not exist "%INSTALLER%" goto :install_failed

echo     Running silent installer (per-user, adds to PATH, includes pip) ...
"%INSTALLER%" /quiet InstallAllUsers=0 PrependPath=1 Include_pip=1 Include_launcher=1 Include_test=0
if errorlevel 1 goto :install_failed

:post_install
REM Current console PATH is not refreshed after install; locate python.exe directly.
for %%P in (
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
    "%ProgramFiles%\Python312\python.exe"
) do (
    if not defined PY if exist %%P set "PY=%%~P"
)
if not defined PY py -3 -c "print(1)" >nul 2>&1 && set "PY=py -3"
if defined PY goto :found_python

:install_failed
echo.
echo  [!] Could NOT install Python automatically.
echo      Install it manually from https://www.python.org/downloads/
echo      and tick "Add python.exe to PATH" during setup.
echo.
pause
exit /b 1

:found_python
for /f "delims=" %%V in ('%PY% -c "import sys;print('.'.join(map(str,sys.version_info[:3])))" 2^>nul') do set "PYVER_FOUND=%%V"
echo     Found Python %PYVER_FOUND%  ^>^>  %PY%
echo.

REM ---------- [3/4] Upgrade pip ----------
echo [3/4] Upgrading pip ...
%PY% -m pip install --upgrade pip >nul 2>&1
echo     done
echo.

REM ---------- [4/4] Install dependencies ----------
echo [4/4] Installing project dependencies ...
if exist "%REQ%" (
    %PY% -m pip install -r "%REQ%"
    if errorlevel 1 (
        echo.
        echo  [!] Some dependencies failed to install. See messages above.
        echo      Optional: without "send2trash" the app deletes permanently
        echo      instead of moving files to Recycle Bin.
    )
) else (
    echo     requirements.txt not next to this script - installing send2trash directly.
    %PY% -m pip install send2trash
)
echo.

echo ============================================================
echo   All done!  You can now launch the app with run.bat
echo ============================================================
echo.
set /p RUNNOW="Start Disk Cleaner now? (y/N): "
if /i "!RUNNOW!"=="y" (
    start "" %PY% "%ROOT%disk_cleaner.py"
) else (
    echo     Run it later by double-clicking run.bat
)
echo.
endlocal
pause
