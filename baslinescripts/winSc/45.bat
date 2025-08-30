@echo off
sc query "WINS" | findstr /C:"STATE" > result.txt
if %errorlevel% == 1 (
    echo null
    exit /b 1
    del "result.txt" /q
) else (
    for /f "tokens=4" %%A in ('type result.txt ^| findstr /C:"STATE"') do set winsStatus=%%A
    if /i "%winsStatus%" NEQ "STOPPED" (
        del "result.txt" /q
        exit /b 0
    ) else (
        del "result.txt" /q
        exit /b 1
    )
)
