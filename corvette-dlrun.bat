@echo off

set CORVETTE_HOME=%TEMP%\corvette
set CORVETTE_SAVE_AS=%CORVETTE_HOME%\corvette.ps1
set CORVETTE_SAVE_AS_TMP=%CORVETTE_HOME%\corvette.ps1.tmp
set CORVETTE_URL=https://github.com/spearmin10/corvette/blob/main/corvette.ps1?raw=true

if not exist "%CORVETTE_HOME%" (
  mkdir "%CORVETTE_HOME%"
  if errorlevel 1 (
    echo Failed to create a folder: %CORVETTE_HOME%
    exit /b 1
  )
)

curl -Lo "%CORVETTE_SAVE_AS_TMP%" -H "Cache-Control: no-cache, no-store" "%CORVETTE_URL%" 2> NUL
if errorlevel 1 (
  echo Failed to download corvette.ps1
) else (
  if exist "%CORVETTE_SAVE_AS%" (
    fc /b "%CORVETTE_SAVE_AS_TMP%" "%CORVETTE_SAVE_AS%" > NUL 2>&1
    if errorlevel 1 (
      rem Clean up the cache
      pushd "%CORVETTE_HOME%"
      for /F "usebackq" %%i in (`dir /B /A:D`) do (
        rmdir /S /Q "%%i" > NUL 2>&1
      )
      for /F "usebackq" %%i in (`dir /B`) do (
	    echo %%~fi
        if not "%%i"=="corvette.json" (
          if not "%%i"=="corvette.ps1" (
            if not "%%i"=="corvette.ps1.tmp" (
              del /S /Q "%%i" > NUL 2>&1
            )
          )
        )
      )
      popd
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
