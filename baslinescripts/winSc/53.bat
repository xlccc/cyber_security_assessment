@echo off
setlocal enabledelayedexpansion

w32tm /query /configuration | findstr "NtpServer" > result.txt
set /p ntpServer=<result.txt
if /i "!ntpServer!" == "" (
    del result.txt
    exit /b 0
) else (
    del result.txt
    exit /b 1
)

endlocal