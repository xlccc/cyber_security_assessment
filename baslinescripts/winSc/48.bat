@echo off
setlocal enabledelayedexpansion
sc query "LanmanServer" | find "RUNNING" > nul
if %errorlevel% == 1 (
    echo null
    exit /b 1
)else (
    for /f "tokens=1" %%a in ('net share ^| findstr /r "^[A-Za-z]"') do (
        set "shareName=%%a"
        if not "!shareName!"=="" (
            echo Checking share: !shareName!
            set "foundEveryone=0"
            for /f "tokens=*" %%b in ('net share !shareName! ^| find "Everyone"') do (
                if not "%%b"=="" (
                    set "foundEveryone=1"
                    exit /b 0
                )
            )
            if !foundEveryone!==0 (
                exit /b 1
            )
        )
    )
)
endlocal
