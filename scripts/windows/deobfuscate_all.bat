@echo off
setlocal EnableExtensions EnableDelayedExpansion
call "%~dp0config.bat" || exit /b 1

if not exist "%DEOBF_ALL%" (
    echo [ERROR] Deobfuscator entry point not found: %DEOBF_ALL% 1>&2
    exit /b 1
)
where "%PYTHON%" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python command not found: %PYTHON% 1>&2
    exit /b 1
)
if not exist "%DEOBFUSCATED_DIR%\" mkdir "%DEOBFUSCATED_DIR%" || exit /b 1

>"%DEOBF_LOG%" echo.

if not "%~1"=="" goto :arguments
set "FOUND=0"
for %%F in ("%DECOMPILED_DIR%\*.dec.pkl") do if exist "%%~fF" (
    set "FOUND=1"
    call :process "%%~fF" || exit /b 1
)
if "%FOUND%"=="0" (
    echo [ERROR] No .dec.pkl files found in: %DECOMPILED_DIR% 1>&2
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
set "BASE=!NAME:.dec.pkl=!"
set "OUTPUT=%DEOBFUSCATED_DIR%\!BASE!.deobf.txt"

call :log ============================================================
call :log Processing: %INPUT%
call :log Output:     !OUTPUT!
call :log Started:    %DATE% %TIME%

echo Running deobfuscator; detailed output is appended to:
echo   %DEOBF_LOG%
"%PYTHON%" -u "%DEOBF_ALL%" --inp "%INPUT%" --out "!OUTPUT!" >>"%DEOBF_LOG%" 2>&1
if errorlevel 1 (
    call :log ERROR: Deobfuscation failed for %INPUT%
    exit /b 1
)
call :log Finished:   %INPUT%
call :log Completed:  %DATE% %TIME%
exit /b 0

:log
echo %*
echo %*>>"%DEOBF_LOG%"
exit /b 0

:done
call :log All files deobfuscated successfully.
exit /b 0
