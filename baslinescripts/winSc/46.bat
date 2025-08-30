@echo off
sc query "SimpleTCP" | findstr /C:"STATE" > result.txt
if %errorlevel% == 1 (
    echo null
    del "result.txt" /q
    exit /b 1
) else (
    for /f "tokens=4" %%A in ('type result.txt ^| findstr /C:"STATE"') do set simpleTcpStatus=%%A
    if /i "%simpleTcpStatus%" NEQ "STOPPED" (
        del "result.txt" /q
        exit /b 0
    ) else (
        del "result.txt" /q
        exit /b 1
    )
)