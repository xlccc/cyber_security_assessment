# 强制PowerShell输出使用UTF-8编码
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
# 导出安全策略配置到临时文件
$seceditExportPath = "C:\secpol_temp.cfg"
secedit /export /cfg $seceditExportPath

# 查找并提取密码复杂性相关的内容
$complexitySetting = Select-String -Path $seceditExportPath -Pattern "PasswordComplexity" | ForEach-Object {
    $_.Line
}

# 检查密码复杂性是否启用
if ($complexitySetting -match "PasswordComplexity\s*=\s*1") {
    Write-Host 1
} elseif ($complexitySetting -match "PasswordComplexity\s*=\s*0") {
    Write-Host 0
} else {
    Write-Host -1
}

# 清理临时文件
Remove-Item $seceditExportPath
