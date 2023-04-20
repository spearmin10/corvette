@echo off

set CORVETTE_SAVE_AS=%TEMP%\corvette.ps1
set CORVETTE_URL=https://github.com/spearmin10/corvette/blob/main/corvette.ps1?raw=true

curl -Lo "%CORVETTE_SAVE_AS%" "%CORVETTE_URL%" 2> NUL

powershell -ExecutionPolicy ByPass "%CORVETTE_SAVE_AS%"
pause

