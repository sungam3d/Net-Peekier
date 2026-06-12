@echo off
:: ================================================
:: Run Python Script as Administrator
:: ================================================

:: Check if we already have admin rights
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Running with Administrator privileges.
    goto :run
) else (
    echo [INFO] Requesting Administrator privileges...
)

:: Request admin rights
setlocal EnableDelayedExpansion
set "params=%*"
set "script=%~f0"

:: Create VBS to relaunch as admin
echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
echo UAC.ShellExecute "cmd.exe", "/c ""%script%"" %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

"%temp%\getadmin.vbs"
del "%temp%\getadmin.vbs"
exit /B

:run
:: ------------------ Change these if needed ------------------
set "PYTHON_SCRIPT=run.py"
:: ------------------------------------------------------------

echo.
echo ================================================
echo Launching: %PYTHON_SCRIPT%
echo ================================================

pushd "%~dp0"
python "%PYTHON_SCRIPT%"

echo.