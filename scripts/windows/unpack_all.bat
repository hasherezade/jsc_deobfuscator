@echo off
setlocal EnableExtensions EnableDelayedExpansion
call "%~dp0config.bat" || exit /b 1

if not exist "%UNPACKED_DIR%\" mkdir "%UNPACKED_DIR%" || exit /b 1

if /i "%DECOMPRESS_METHOD%"=="js" goto :check_js
if /i "%DECOMPRESS_METHOD%"=="brotli" goto :check_brotli

echo [ERROR] Unknown DECOMPRESS_METHOD: %DECOMPRESS_METHOD% 1>&2
echo         Expected: js or brotli 1>&2
exit /b 1

:check_js
where "%NODE%" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js command not found: %NODE% 1>&2
    exit /b 1
)
if not exist "%DECOMPRESS_JSC%" (
    echo [ERROR] Decompression helper not found: %DECOMPRESS_JSC% 1>&2
    exit /b 1
)
goto :dispatch

:check_brotli
where "%BROTLI%" >nul 2>&1
if errorlevel 1 if not exist "%BROTLI%" (
    echo [ERROR] Brotli CLI not found: %BROTLI% 1>&2
    echo         See README.md for installation/build options. 1>&2
    exit /b 1
)
goto :dispatch

:dispatch
if not "%~1"=="" goto :arguments
set "FOUND=0"
for %%F in ("%PAYLOADS_DIR%\*.jsc.br") do if exist "%%~fF" (
    set "FOUND=1"
    call :process "%%~fF" || exit /b 1
)
if "%FOUND%"=="0" (
    echo [ERROR] No .jsc.br files found in: %PAYLOADS_DIR% 1>&2
    exit /b 1
)
goto :done

:arguments
:argument_loop
if "%~1"=="" goto :done
call :process "%~1" || exit /b 1
shift
goto :argument_loop

:process
set "INPUT=%~f1"
if not exist "%INPUT%" (
    echo [ERROR] File not found: %INPUT% 1>&2
    exit /b 1
)
set "NAME=%~nx1"
set "OUTNAME=!NAME:.br=!"
set "OUTPUT=%UNPACKED_DIR%\!OUTNAME!"

echo Processing: %INPUT%
echo Output:     !OUTPUT!

if /i "%DECOMPRESS_METHOD%"=="brotli" (
    "%BROTLI%" -d -k -f "%INPUT%" -o "!OUTPUT!"
    if errorlevel 1 (
        echo [ERROR] Brotli decompression failed: %INPUT% 1>&2
        exit /b 1
    )
    exit /b 0
)

rem decompress-jsc.js writes ^<input^>.decompressed.jsc next to the input.
set "GENERATED=%INPUT%.decompressed.jsc"
if exist "!GENERATED!" del /q "!GENERATED!" >nul 2>&1
"%NODE%" "%DECOMPRESS_JSC%" "%INPUT%"
if errorlevel 1 (
    echo [ERROR] JavaScript decompression failed: %INPUT% 1>&2
    exit /b 1
)
if not exist "!GENERATED!" (
    echo [ERROR] Expected output was not produced: !GENERATED! 1>&2
    exit /b 1
)
move /y "!GENERATED!" "!OUTPUT!" >nul || exit /b 1
exit /b 0

:done
echo All payloads decompressed successfully.
exit /b 0
