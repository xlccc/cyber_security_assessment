# 强制PowerShell输出使用UTF-8编码
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
# 导出当前系统的安全策略到临时文件
$secpolFile = "C:\secpol_temp.cfg"
secedit /export /cfg $secpolFile

# 读取文件并查找"SeInteractiveLogonRight"策略配置
$CheckLocalNetworkAccessLine = Select-String -Path $secpolFile -Pattern "SeInteractiveLogonRight"

# 如果没有找到该策略，则返回 -1
if (-not $CheckLocalNetworkAccessLine) {
    Write-Output -1
    Remove-Item $secpolFile
    return
}

# 获取当前配置的账户列表
$CheckLocalNetworkAccessAccounts = $CheckLocalNetworkAccessLine.Line -split "=" | Select-Object -Last 1
$CheckLocalNetworkAccessAccounts = $CheckLocalNetworkAccessAccounts.Trim()

# 允许的账户列
$validAccounts = @("*S-1-5-32-544", "BUILTIN\Administrators", "Administrators", 
                   "*S-1-5-11", "NT AUTHORITY\Authenticated Users", "Authenticated Users",
                   "*S-1-5-18", "NT AUTHORITY\SYSTEM", "SYSTEM")

# 检查配置的账户是否仅包含有效账户
$invalidAccounts = $CheckLocalNetworkAccessAccounts.Split(",") | Where-Object { $_ -notin $validAccounts }

if ($invalidAccounts.Count -eq 0) {
    # 只有有效账户
    Write-Output 1
} else {
    # 存在无效账户
    Write-Output 0
}

# 删除临时文件
Remove-Item $secpolFile
