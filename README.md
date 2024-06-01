配置：

1、端口扫描是通过集成nmap来实现的，nmap需要特权才能进行完整扫描，所以需要当前默认用户在执行nmap时默认无需密码：
修改 /etc/sudoers 文件：以允许用户在执行特定命令时不需要密码。例如：

your_user_name ALL=(ALL) NOPASSWD: /usr/bin/nmap
your_user_name ALL=(ALL) NOPASSWD: /bin/chown                                         
your_user_name ALL=(ALL) NOPASSWD: /bin/chmod

2、nmap端口扫描功能需要配置输出结果output_nmap路径：
以普通用户user在out目录下：
mkdir output_nmap //并保证其有足够的权限

在scan/portScan.cpp中：
设置例如：outputPath = "../../output_nmap/" + outputFileName; //具体应为实际路径。

