@echo off

set CORVETTE_HOME=%TEMP%\corvette
set CORVETTE_SAVE_AS=%TEMP%\corvette.ps1
set CORVETTE_SAVE_AS_TMP=%TEMP%\corvette.ps1.tmp
set CORVETTE_URL=https://github.com/spearmin10/corvette/blob/main/corvette.ps1?raw=true

curl -Lo "%CORVETTE_SAVE_AS_TMP%" -H "Cache-Control: no-cache, no-store" "%CORVETTE_URL%" 2> NUL
if errorlevel 1 (
  echo Failed to download corvette.ps1
) else (
  if exist "%CORVETTE_SAVE_AS%" (
    if exist "%CORVETTE_HOME%" (
      fc /b "%CORVETTE_SAVE_AS_TMP%" "%CORVETTE_SAVE_AS%" > NUL 2>&1
      if errorlevel 1 (
        rem Clean up the cache
        pushd "%CORVETTE_HOME%"
        for /F "usebackq" %%i in (`dir /B /A:D`) do (
          rmdir /S /Q "%%i" > NUL 2>&1
        )
        for /F "usebackq" %%i in (`dir /B`) do (
          if not "%%i"=="corvette.json" (
            del /S /Q "%%i" > NUL 2>&1
          )
        )
        popd
      )
    )
  )
  move /Y "%CORVETTE_SAVE_AS_TMP%" "%CORVETTE_SAVE_AS%" > NUL 2>&1
)

if not exist "%CORVETTE_SAVE_AS%" (
  echo corvette.ps1 doesn't exist.
) else (
  powershell -ExecutionPolicy ByPass "%CORVETTE_SAVE_AS%"
)
pause
