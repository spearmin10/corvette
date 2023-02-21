set TMP_DIR=%TEMP%\%random:~-2%%random:~-2%%random:~-2%%random:~-2%.tmp

call powershell Expand-Archive corvette-office-files.zip -DestinationPath "%TMP_DIR%" -Force

pushd "%TMP_DIR%"
rename "corvette wmi.doc" "���ē� wmi.doc"
rename "corvette.doc" "���ē�.doc"
rename "corvette wmi.xls" "�\���� wmi.xls"
rename "corvette.xls" "�\����.xls"
rename "corvette-mini wmi (offline).doc" "OFF��Q���\�� wmi.doc"
rename "corvette-mini (offline).doc" "OFF��Q���\��.doc"
rename "corvette-mini wmi (offline).xls" "OFF��Q���o�^ wmi.xls"
rename "corvette-mini (offline).xls" "OFF��Q���o�^.xls"
popd

call powershell Compress-Archive "%TMP_DIR%\*" corvette-office-files-jp.zip
del /S /Q "%TMP_DIR%"

pause
