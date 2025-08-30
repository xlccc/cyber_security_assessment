@echo off
setlocal enabledelayedexpansion

bcdedit | find "nx" > result.txt
if errorlevel neq 0 (
    echo null
    del result.txt
    exit 0
)

set /p depStatus=<result.txt
del result.txt
if "!depStatus!" == "" (
    exit /b 0
) else (
    exit /b 1
)

endlocal