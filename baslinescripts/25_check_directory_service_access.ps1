# 强制PowerShell输出使用UTF-8编码
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
# 导出当前系统的安全策略到临时文件
$secpolFile = "C:\secpol_temp.cfg"
secedit /export /cfg $secpolFile

# 读取文件并查找"Audit Directory Service Access"策略配置
$CheckAuditDirectoryServiceAccessLine = Select-String -Path $secpolFile -Pattern "AuditDSAccess"

# 如果没有找到该策略，则返回 -1
if (-not $CheckAuditDirectoryServiceAccessLine) {
    Write-Output -1
    Remove-Item $secpolFile
    return
}

# 获取当前配置的审计策略
$AuditDirectoryServiceAccessConfig = $CheckAuditDirectoryServiceAccessLine.Line -split "=" | Select-Object -Last 1
$AuditDirectoryServiceAccessConfig = $AuditDirectoryServiceAccessConfig.Trim()



    Write-Output $AuditDirectoryServiceAccessConfig
# 删除临时文件
Remove-Item $secpolFile
