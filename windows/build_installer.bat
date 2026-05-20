@echo off
setlocal
set ROOT=%~dp0..
set OUTDIR=%ROOT%\Output\build_%RANDOM%%RANDOM%

where ISCC.exe >nul 2>nul
if %errorlevel%==0 (
  pushd "%ROOT%"
  ISCC.exe /O"%OUTDIR%" "windows\installer.iss"
  popd
  if errorlevel 1 goto :build_failed
  goto :build_ok
)

if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" (
  pushd "%ROOT%"
  "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" /O"%OUTDIR%" "windows\installer.iss"
  popd
  if errorlevel 1 goto :build_failed
  goto :build_ok
)

if exist "C:\Program Files\Inno Setup 6\ISCC.exe" (
  pushd "%ROOT%"
  "C:\Program Files\Inno Setup 6\ISCC.exe" /O"%OUTDIR%" "windows\installer.iss"
  popd
  if errorlevel 1 goto :build_failed
  goto :build_ok
)

if exist "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" (
  pushd "%ROOT%"
  "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" /O"%OUTDIR%" "windows\installer.iss"
  popd
  if errorlevel 1 goto :build_failed
  goto :build_ok
)

echo Inno Setup Compiler (ISCC.exe) not found.
echo Install Inno Setup from: https://jrsoftware.org/isinfo.php
exit /b 1

:build_ok
echo Installer build complete. Output: %OUTDIR%
exit /b 0

:build_failed
echo Installer build failed. If you see resource update error 110, close running installer/exe and temporarily exclude the Output folder from antivirus.
exit /b 1
