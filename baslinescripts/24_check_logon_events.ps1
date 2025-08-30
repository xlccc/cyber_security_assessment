# 强制PowerShell输出使用UTF-8编码
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
# 导出当前系统的安全策略到临时文件
$secpolFile = "C:\secpol_temp.cfg"
secedit /export /cfg $secpolFile

# 读取文件并查找"AuditLogonEvents "策略配置
$CheckAuditLogonEventsLine = Select-String -Path $secpolFile -Pattern "AuditLogonEvents "

# 如果没有找到该策略，则返回 -1
if (-not $CheckAuditLogonEventsLine) {
    Write-Output -1
    Remove-Item $secpolFile
    return
}

# 获取当前配置的审计策略
$AuditLogonEventsConfig = $CheckAuditLogonEventsLine.Line -split "=" | Select-Object -Last 1
$AuditLogonEventsConfig = $AuditLogonEventsConfig.Trim()





    Write-Output $AuditLogonEventsConfig


# 删除临时文件
Remove-Item $secpolFile
