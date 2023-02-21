@echo off
set TMP_DIR=%TEMP%\%random:~-2%%random:~-2%%random:~-2%%random:~-2%.tmp
set SRC_ARCHIVE=corvette-office-files.zip
set DST_ARCHIVE=corvette-office-files-jp.zip

if not exist "%SRC_ARCHIVE%" (
  echo %SRC_ARCHIVE% was not found.
  pause
  exit /b 1
)

call powershell Expand-Archive "%SRC_ARCHIVE%" -DestinationPath "%TMP_DIR%" -Force

pushd "%TMP_DIR%"
rename "corvette wmi.doc" "‚²ˆÄ“à wmi.doc"
rename "corvette.doc" "‚²ˆÄ“à.doc"
rename "corvette wmi.xls" "\ž‘ wmi.xls"
rename "corvette.xls" "\ž‘.xls"
rename "corvette-mini wmi (offline).doc" "OFF‰ïŽQ‰Á\¿ wmi.doc"
rename "corvette-mini (offline).doc" "OFF‰ïŽQ‰Á\¿.doc"
rename "corvette-mini wmi (offline).xls" "OFF‰ïŽQ‰Á“o˜^ wmi.xls"
rename "corvette-mini (offline).xls" "OFF‰ïŽQ‰Á“o˜^.xls"
popd

call powershell Compress-Archive "%TMP_DIR%\*" "%DST_ARCHIVE%" -Force
del /S /Q "%TMP_DIR%" > NUL

pause
