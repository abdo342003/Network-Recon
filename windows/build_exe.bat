@echo off
REM Build a single-file Windows executable via windows/network_recon.spec (PyInstaller).
SETLOCAL
setlocal EnableDelayedExpansion
set ROOT=%~dp0..
set SPEC=%~dp0network_recon.spec
set PYTHON="%ROOT%\.venv\Scripts\python.exe"
if not exist %PYTHON% (
  echo Virtualenv not found. Run install.bat first to create .venv and install deps.
  exit /b 1
)

set EXE_NAME=network_recon
for /f "tokens=*" %%A in ('powershell -NoProfile -Command "if (Get-Process ^| Where-Object { $_.ProcessName -like ''network_recon*'' } ) { '1' } else { '0' }"') do set PROCESS_RUNNING=%%A
if "%PROCESS_RUNNING%"=="1" (
  for /f "tokens=*" %%B in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set BUILD_STAMP=%%B
  set EXE_NAME=network_recon_build_!BUILD_STAMP!
  echo network_recon.exe is already running; building alternate output: !EXE_NAME!.exe
) else (
  if exist "%ROOT%\dist\network_recon.exe" (
    del /F /Q "%ROOT%\dist\network_recon.exe" >nul 2>&1
  )
)

if exist "%ROOT%\build\network_recon" (
  rmdir /S /Q "%ROOT%\build\network_recon" >nul 2>&1
)

set NETWORK_RECON_EXE_NAME=%EXE_NAME%

%PYTHON% -m pip install --upgrade pip wheel pyinstaller
if not exist "%ROOT%\assets\app.ico" (
  echo Creating placeholder assets\app.ico ...
  %PYTHON% -m pip install pillow --quiet
  %PYTHON% "%ROOT%\assets\create_placeholder_icon.py"
)

pushd "%ROOT%"
%PYTHON% -m PyInstaller --noconfirm --clean "%SPEC%"
popd
if errorlevel 1 (
  echo PyInstaller failed.
  exit /b 1
)
echo.
echo Build complete: "%ROOT%\dist\!EXE_NAME!.exe"
echo Version is defined in pyproject.toml and windows/installer.iss.
ENDLOCAL
