@echo off
setlocal enabledelayedexpansion
wmic logicaldisk get name, filesystem > result.txt

REM 定义一个变量来保存所有文件系统格式
set "filesystems="

REM 处理结果文件
for /f "skip=1" %%c in (result.txt) do (
    if "%%c"=="" (
        set /a skippedCount+=1
    ) else (
        set "line=%%c"
        
        REM 解析驱动器和文件系统
        for /f "tokens=1,2" %%d in ("!line!") do (
            set "filesystem=%%e"
            REM 添加文件系统到列表
            if not "!filesystem!"=="" (
                set "filesystems=!filesystems! !filesystem!"
            )
        )
    )
)

REM 删除多余空格
set "filesystems=!filesystems: =!"

REM 检查所有文件系统是否都是 NTFS
set "allNTFS=true"

for %%f in (!filesystems!) do (
    if /i "%%f" neq "NTFS" (
        set "allNTFS=false"
    )
)

REM 判断所有检查是否符合条件
if "!allNTFS!"=="true" (
    del result.txt
    exit /b 1
) else (
    del result.txt
    exit /b 0
)

endlocal