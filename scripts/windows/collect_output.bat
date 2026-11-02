@echo off
setlocal EnableExtensions EnableDelayedExpansion
call "%~dp0config.bat" || exit /b 1

if %HARVEST_PREFIX_LENGTH% LSS 1 (
    echo [ERROR] HARVEST_PREFIX_LENGTH must be a positive integer. 1>&2
    exit /b 1
)
if not exist "%HARVEST_DIR%\" mkdir "%HARVEST_DIR%" || exit /b 1

set "FOUND=0"
for %%F in ("%DECOMPILED_DIR%\*.dec.resolved_funcs.csv") do if exist "%%~fF" (
    set "FOUND=1"
    set "NAME=%%~nxF"
    set "SAMPLE=!NAME:.dec.resolved_funcs.csv=!"
    set "PREFIX=!SAMPLE:~0,%HARVEST_PREFIX_LENGTH%!"
    set "DEST=%HARVEST_DIR%\!PREFIX!"
    if not exist "!DEST!\" mkdir "!DEST!" || exit /b 1
    copy /y "%%~fF" "!DEST!\" >nul || exit /b 1

    set "STRINGS=%DEOBFUSCATED_DIR%\!SAMPLE!.deobf.txt.strings.txt"
    if exist "!STRINGS!" (
        copy /y "!STRINGS!" "!DEST!\" >nul || exit /b 1
    ) else (
        echo [WARNING] Missing !STRINGS!
    )
)

if "%FOUND%"=="0" (
    echo [ERROR] No resolved-functions CSV files found in: %DECOMPILED_DIR% 1>&2
    exit /b 1
)

echo Collected output under: %HARVEST_DIR%
exit /b 0
