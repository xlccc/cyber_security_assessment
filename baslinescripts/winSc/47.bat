@echo off
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon > result.txt 2>&1
if %errorlevel% NEQ 0 (
    echo null
    del "result.txt" /q
    exit /b 1
) else (
    for /f "tokens=3" %%a in ('reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon') do (
        if "%%a" NEQ "0x0" (
            del "result.txt" /q
            exit /b 0
        ) else (
            del "result.txt" /q
            exit /b 1
        )
    )
)