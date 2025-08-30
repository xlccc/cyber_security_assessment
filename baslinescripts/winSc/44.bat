@echo off
sc query "SMTPSVC" | findstr /C:"STATE" > result.txt
if %errorlevel% == 1 (
    echo null
    exit /b 1
) else (
    for /f "tokens=3" %%A in ('type result.txt ^| findstr /C:"STATE"') do set smtpStatus=%%A
    if /i "%smtpStatus%" NEQ "STOPPED" (
        del "result.txt" /q
        exit /b 0
    ) else (
        del "result.txt" /q
        exit /b 1
    )
)
