# 强制UTF-8输出（避免SSH中文乱码）
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
# 执行 net user 命令并获取输出
$output = net user

# 查找“-------------------------------------------------------------------------------”和“命令成功完成”之间的部分
$startLine = $false
$accountCount = 0

foreach ($line in $output) {
    # 当遇到“-------------------------------------------------------------------------------”时，开始计数
    if ($line -match "^-+$") {
        $startLine = !$startLine
        continue
    }

    # 如果在“-------------------------------------------------------------------------------”和“命令成功完成”之间，统计账户名
    if ($startLine -and $line -notmatch "The command completed successfully") {
        # 过滤掉空行或无效行
        if ($line.Trim() -ne "") {
            $accountCount++
        }
    }

    # 如果遇到“命令成功完成”，停止计数
    if ($line -match "The command completed successfully") {
        break
    }
}

# 输出账户数量
Write-Host "$accountCount"
