@echo off
setlocal
set ROOT=%~dp0..
if exist "%ROOT%\.venv\Scripts\python.exe" (
  "%ROOT%\.venv\Scripts\python.exe" "%ROOT%\scripts\install.py"
) else (
  py -3 "%ROOT%\scripts\install.py"
)
endlocal
