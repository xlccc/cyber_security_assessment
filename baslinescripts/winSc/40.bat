@echo off
sc query "RemoteAccess" | findstr /C:"STATE" > result.txt
for /f "tokens=4" %%A in ('type result.txt ^| findstr /C:"STATE"') do set remoteAccessStatus=%%A
if /i "%remoteAccessStatus%" NEQ "STOPPED" (
    del "result.txt" /q
    exit /b 0
) else (
    del "result.txt" /q
    exit /b 1
)


