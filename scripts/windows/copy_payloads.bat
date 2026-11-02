@echo off
setlocal EnableExtensions EnableDelayedExpansion
call "%~dp0config.bat" || exit /b 1

if not "%~1"=="" set "SOURCE_DIR=%~1"
if not exist "%SOURCE_DIR%\" (
    echo [ERROR] Source directory not found: %SOURCE_DIR% 1>&2
    exit /b 1
)
if not exist "%PAYLOADS_DIR%\" mkdir "%PAYLOADS_DIR%" || exit /b 1

set "FOUND=0"
for /r "%SOURCE_DIR%" %%F in (app.js*) do (
    if exist "%%~fF" (
        set "FOUND=1"
        set "HASH="
        for /f "skip=1 tokens=*" %%H in ('certutil -hashfile "%%~fF" MD5 2^>nul') do if not defined HASH set "HASH=%%H"
        set "HASH=!HASH: =!"
        if not defined HASH (
            echo [ERROR] Failed to calculate MD5: %%~fF 1>&2
            exit /b 1
        )
        set "DEST=%PAYLOADS_DIR%\!HASH!.jsc.br"
        copy /y "%%~fF" "!DEST!" >nul || exit /b 1
        echo Copied: %%~fF ^-^> !DEST!
    )
)

if "%FOUND%"=="0" (
    echo [ERROR] No app.js* files found under: %SOURCE_DIR% 1>&2
    exit /b 1
)

echo Payloads copied to: %PAYLOADS_DIR%
exit /b 0
