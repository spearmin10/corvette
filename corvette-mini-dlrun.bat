@echo off
set CORVETTE_SAVE_AS=%TEMP%\corvette-mini.ps1
set CORVETTE_URL=https://github.com/spearmin10/corvette/blob/main/corvette-mini.ps1?raw=true

curl -Lo "%CORVETTE_SAVE_AS%" -H "Cache-Control: no-cache, no-store" "%CORVETTE_URL%" 2> NUL

for /f "usebackq delims=" %%i in (`powershell -Command "[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes([System.IO.File]::ReadAllText('%CORVETTE_SAVE_AS%')))"`) do set CORVETTE_B64=%%i

powershell -e "%CORVETTE_B64%"
pause

