set TMP_DIR=%TEMP%\%random:~-2%%random:~-2%%random:~-2%%random:~-2%.tmp

call powershell Expand-Archive corvette-office-files.zip -DestinationPath "%TMP_DIR%" -Force

pushd "%TMP_DIR%"
rename "corvette wmi.doc" "ご案内 wmi.doc"
rename "corvette.doc" "ご案内.doc"
rename "corvette wmi.xls" "申込書 wmi.xls"
rename "corvette.xls" "申込書.xls"
rename "corvette-mini wmi (offline).doc" "OFF会参加申請 wmi.doc"
rename "corvette-mini (offline).doc" "OFF会参加申請.doc"
rename "corvette-mini wmi (offline).xls" "OFF会参加登録 wmi.xls"
rename "corvette-mini (offline).xls" "OFF会参加登録.xls"
popd

call powershell Compress-Archive "%TMP_DIR%\*" corvette-office-files-jp.zip
del /S /Q "%TMP_DIR%"

pause
