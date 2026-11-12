@echo off
setlocal EnableExtensions EnableDelayedExpansion
call "%~dp0config.bat" || exit /b 1

if not exist "%VIEW8%" (
    echo [ERROR] View8 entry point not found: %VIEW8% 1>&2
    exit /b 1
)
if not exist "%PYTHON%" (
    where "%PYTHON%" >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Python command not found: %PYTHON% 1>&2
        exit /b 1
    )
)
if not exist "%DECOMPILED_DIR%\" mkdir "%DECOMPILED_DIR%" || exit /b 1

if not "%~1"=="" goto :arguments
set "FOUND=0"
for %%F in ("%DISASSEMBLED_DIR%\*.jsc.disasm.txt") do if exist "%%~fF" (
    set "FOUND=1"
    call :process "%%~fF" || exit /b 1
)
if "%FOUND%"=="0" (
    echo [ERROR] No .jsc.disasm.txt files found in: %DISASSEMBLED_DIR% 1>&2
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
set "BASE=!NAME:.jsc.disasm.txt=!"
set "OUTPUT=%DECOMPILED_DIR%\!BASE!.dec.txt"

echo Processing: %INPUT%
echo Output:     !OUTPUT!
"%PYTHON%" "%VIEW8%" --input_format disassembled --inp "%INPUT%" --normalize --out "!OUTPUT!" --export_format decompiled serialized
if errorlevel 1 (
    echo [ERROR] View8 failed: %INPUT% 1>&2
    exit /b 1
)
exit /b 0

:done
echo All files decompiled successfully.
exit /b 0
