@echo off
setlocal EnableExtensions EnableDelayedExpansion
call "%~dp0config.bat" || exit /b 1

if not exist "%V8DASM%" (
    echo [ERROR] V8 disassembler not found: %V8DASM% 1>&2
    exit /b 1
)
if not exist "%DISASSEMBLED_DIR%\" mkdir "%DISASSEMBLED_DIR%" || exit /b 1

if not "%~1"=="" goto :arguments
set "FOUND=0"
for %%F in ("%UNPACKED_DIR%\*.jsc") do if exist "%%~fF" (
    set "FOUND=1"
    call :process "%%~fF" || exit /b 1
)
if "%FOUND%"=="0" (
    echo [ERROR] No .jsc files found in: %UNPACKED_DIR% 1>&2
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
set "OUTPUT=%DISASSEMBLED_DIR%\%~nx1.disasm.txt"
set "TEMP=!OUTPUT!.tmp.%RANDOM%%RANDOM%"

echo Processing: %INPUT%
echo Output:     !OUTPUT!
"%V8DASM%" "%INPUT%" "!TEMP!"
if errorlevel 1 (
    if exist "!TEMP!" del /q "!TEMP!" >nul 2>&1
    echo [ERROR] Disassembly failed: %INPUT% 1>&2
    exit /b 1
)
move /y "!TEMP!" "!OUTPUT!" >nul || exit /b 1
exit /b 0

:done
echo All payloads disassembled successfully.
exit /b 0
