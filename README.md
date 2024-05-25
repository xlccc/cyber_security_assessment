配置：

nmap端口扫描功能需要配置输出结果output_nmap路径：
以普通用户user在out目录下：
mkdir output_nmap //并保证其有足够的权限

在scan/utils_scan.cpp中：
设置例如：outputPath = "../../output_nmap/" + outputFileName; //具体应为实际路径。

