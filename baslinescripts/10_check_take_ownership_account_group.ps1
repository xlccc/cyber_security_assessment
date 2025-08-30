# 强制PowerShell输出使用UTF-8编码
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
# 导出当前系统的安全策略到文件
$secpolFile = "C:\secpol.inf"
secedit /export /cfg $secpolFile

# 读取文件并查找"SeTakeOwnershipPrivilege"策略配置
$takeOwnershipLine = Select-String -Path $secpolFile -Pattern "SeTakeOwnershipPrivilege"

# 如果没有找到该策略，则返回 -1
if (-not $takeOwnershipLine) {
    Write-Output -1
    return
}

# 获取当前配置的账户列表
$takeOwnershipAccounts = $takeOwnershipLine.Line -split "=" | Select-Object -Last 1
$takeOwnershipAccounts = $takeOwnershipAccounts.Trim()

# 有效的账户列表，只允许 Administrators 和 SYSTEM
$validAccounts = @("*S-1-5-32-544", "BUILTIN\Administrators", "Administrators", "*S-1-5-18", "NT AUTHORITY\SYSTEM", "SYSTEM")

# 检查配置的账户是否仅包含有效账户
$invalidAccounts = $takeOwnershipAccounts.Split(",") | Where-Object { $_ -notin $validAccounts }

if ($invalidAccounts.Count -eq 0) {
    # 只有有效账户
    Write-Output 1
} else {
    # 存在无效账户
    Write-Output 0
}