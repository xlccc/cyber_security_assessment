# 强制PowerShell输出使用UTF-8编码
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
# 导出安全策略配置到临时文件
$seceditExportPath = "C:\secpol_temp.cfg"
secedit /export /cfg $seceditExportPath

# 查找并提取强制密码历史相关的内容
$passwordHistorySetting = Select-String -Path $seceditExportPath -Pattern "PasswordHistorySize" | ForEach-Object {
    $_.Line
}

# 提取强制密码历史的个数
if ($passwordHistorySetting -match "PasswordHistorySize\s*=\s*(\d+)") {
    $passwordHistoryCount = $Matches[1]
    Write-Host $passwordHistoryCount
} else {
    Write-Host -1  # 如果未找到相关设置，返回-1
}

# 清理临时文件
Remove-Item $seceditExportPath