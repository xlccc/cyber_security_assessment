@echo off
setlocal enabledelayedexpansion

for /f "tokens=3" %%a in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v SynAttackProtect 2^>nul') do set SynAttackProtect=%%a

:: 检查是否成功查询到值
if not defined SynAttackProtect (
    echo null
    exit /b 0
)

if "!SynAttackProtect!" NEQ "0x1" (
    exit /b 0
) else (
    exit /b 1
)

endlocal
