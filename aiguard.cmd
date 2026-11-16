@echo off
setlocal
rem AI Egress Guard launcher — double-click or run from cmd.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0aiguard.ps1" %*
if "%~1"=="" pause
