@echo off
sc query "MSMQ" > result.txt
if %errorlevel% == 0 (
    echo null
    exit /b 1
    del "result.txt" /q
) else (
    for /f "tokens=3" %%A in ('type result.txt ^| findstr /C:"STATE"') do set msmqStatus=%%A
    if /i "%msmqStatus%" NEQ "STOPPED" (
        del "result.txt" /q
        exit /b 0
    ) else (
        del "result.txt" /q
        exit /b 1
    )
)
