# 网络安全测试平台
该平台专为系统脆弱性和安全性检测设计，支持 Ubuntu 20.04 操作系统。功能包括资产清点、安全基线检测、安全风险评估和安全等级保护测评，并输出详细的检测报告。

## Requirements
### 操作系统
+ 本平台仅在 **Ubuntu 20.04** 上测试通过，建议在此系统上运行以保证兼容性。

### 外部工具依赖
#### 1.Nmap
+ 用于端口扫描。请安装 `nmap` 工具并进行以下配置，以便平台在无密码情况下执行 Nmap 命令：

```bash
sudo apt-get update
sudo apt-get install -y nmap
配置无密码执行 Nmap 操作：
bash
复制代码
sudo visudo
在文件末尾添加以下内容，将 username 替换为实际的用户名：
javascript
复制代码
username ALL=(ALL) NOPASSWD: /usr/bin/nmap
username ALL=(ALL) NOPASSWD: /bin/chown
username ALL=(ALL) NOPASSWD: /bin/chmod
配置 Nmap 扫描结果文件的输出目录：
bash
复制代码
mkdir -p output_nmap
sudo chown username:username output_nmap
sudo chmod 777 output_nmap
```

#### 2.CVE-Search
平台的漏洞库匹配方式使用 CVE-Search，如未安装，可参考：[https://medium.com/@jieshiun/%E5%A6%82%E4%BD%95%E5%9C%A8-ubuntu-20-04-%E5%AE%89%E8%A3%9D-cve-search-%E4%BC%BA%E6%9C%8D%E5%99%A8-9d045a65cc70](https://medium.com/@jieshiun/%E5%A6%82%E4%BD%95%E5%9C%A8-ubuntu-20-04-%E5%AE%89%E8%A3%9D-cve-search-%E4%BC%BA%E6%9C%8D%E5%99%A8-9d045a65cc70)

#### 3.C++依赖库
本项目使用 vcpkg 进行依赖管理。以下为所需的库：

安装 vcpkg 后，依次执行以下命令：

```bash
vcpkg install libssh
vcpkg install sqlite3 cpprestsdk
vcpkg install icu
vcpkg install curl[core,non-http,openssl,ssl]
vcpkg install pybind11
vcpkg install uchardet
vcpkg install mysql-connector-cpp:x64-linux
```

其他系统依赖安装：

```bash
sudo apt-get update
sudo apt-get install -y autoconf automake autoconf-archive ninja-build
```

说明：如果不使用 vcpkg 管理依赖，可手动安装上述库并确保 CMake 工程能够找到所需头文件和库路径。

#### 4.数据库

将目录下的sql文件在目标服务器先执行。可以利用navicat

### 前端

项目前端网站：https://github.com/attente12/NetSec-testing/tree/master/demo

使用 IntelliJ IDEA 作为开发工具：

1. 打开项目时，确保选择项目根目录。
2. 配置 Node.js 路径：
   - 打开 `File` > `Settings` > `Languages & Frameworks` > `Node.js and NPM`。
   - 指定 Node.js 安装路径。
3. 配置运行/调试任务：
   - 点击右上角的运行配置下拉菜单，选择 `Edit Configurations`。
   - 添加 `npm` 任务，设置 `serve` 为默认任务。

## 现阶段进度
| 总览 | | | | |
| :---: | --- | --- | --- | --- |
| 序号 | 隶属 | 功能 | 是否支持 | 备注 |
| <font style="color:rgb(31, 35, 40);">1</font> | 资产清点 | 主机发现 |  |  |
| <font style="color:rgb(31, 35, 40);">2</font> | | 端口扫描 | √ |  |
| <font style="color:rgb(31, 35, 40);">3</font> | | 网络协议分析工具 |  | He |
| <font style="color:rgb(31, 35, 40);">4</font> | | 资产管理 |  | Huang |
| <font style="color:rgb(31, 35, 40);">5</font> | | 资产面板 |  |  |
| <font style="color:rgb(31, 35, 40);">6</font> | 基线检测 | 等保三级 | √ |  |
| <font style="color:rgb(31, 35, 40);">7</font> | | 等保二级 |  | 在三级基础上划分 |
| <font style="color:rgb(31, 35, 40);">8</font> | | 工信部安全基线标准 |  |  |
| <font style="color:rgb(31, 35, 40);">9</font> | | CIS基线标注 |  |  |
| <font style="color:rgb(31, 35, 40);">10</font> | | 报告输出 | √ |  |
| <font style="color:rgb(31, 35, 40);">11</font> | 风险评估<br/> | 漏洞库匹配 | √ |  |
| <font style="color:rgb(31, 35, 40);">12</font> | | 插件化扫描 | √ |  |
| <font style="color:rgb(31, 35, 40);">13</font> | | 攻击路径分析 |  | Yang |
| <font style="color:rgb(31, 35, 40);">14</font> | | 漏洞挖掘 |  | Ding |
| <font style="color:rgb(31, 35, 40);">15</font> | | 弱口令检测 | √ |  |
| <font style="color:rgb(31, 35, 40);">16</font> | | 防火墙安全策略冲突 |  | FU |
| <font style="color:rgb(31, 35, 40);">17</font> | | 报告输出 |  |  |
| <font style="color:rgb(31, 35, 40);">18</font> | 等级保护测评 | 等保三级 | √ | 常用 |
| <font style="color:rgb(31, 35, 40);">19</font> | | 等保二级 |  | 常用 |
| <font style="color:rgb(31, 35, 40);">20</font> | | 其他等级 |  |  |
| <font style="color:rgb(31, 35, 40);">21</font> | | 考虑基线核查结果 | √ | 主要是配置核查 |
| <font style="color:rgb(31, 35, 40);">22</font> | | 考虑风险评估结果 |  |  |
| <font style="color:rgb(31, 35, 40);">23</font> | | 报告输出 |  |  |
| <font style="color:rgb(31, 35, 40);">24</font> | 威胁检测 | 信誉检测 |  |  |
| <font style="color:rgb(31, 35, 40);">25</font> | | 病毒库检测 |  |  |
| <font style="color:rgb(31, 35, 40);">26</font> | | 代码审查 |  |  |
| <font style="color:rgb(31, 35, 40);">27</font> | | 行为分析 |  |  |
| <font style="color:rgb(31, 35, 40);">28</font> | 总报告输出 | 报告输出 |  | 概括上述测试报告 |


| 资产清点 | | | |
| :---: | --- | --- | --- |
| 序号 | 功能 | 是否支持 | 备注 |
| 1 | 探针式扫描 |  | 能够发现更多配置、系统信息 |
| 2 | 主动扫描 | √ | nmap扫描 |
| 3 | 主机发现 |  |  |
| 4 | IP冲突检测 |  | 主机发现的基础上 |
| 5 | 端口扫描 | √ |  |
| 6 | 协议识别 | √ |  |
| 7 | 服务识别 | √ |  |
| 8 | 操作系统识别 | √ |  |
| 9 | 版本识别 | √ | 包含服务、操作系统版本 |
| 10 | nmap扫描<br/>结果解析 | √ | xml文件解析 |
| 11 | 资产管理 |  | Huang |
| 12 | 资产分类 |  | Huang |
| 13 | 资产面板 |  |  |
| 14 | DNS域名解析 |  | 使系统支持对域名扫描 |
| 15 | 网段扫描 |  | 比如对一个C段上所有<br/>存活主机进行扫描。 |
| 16 | 多线程 |  |  |


| 基线检测 | | | |
| :---: | --- | --- | --- |
| 序号 | 类型 | 是否支持 | 备注 |
| 1 | 等保三级 | √ |  |
| 2 | 等保二级 |  | 在三级基础上划分 |
| 3 | 工信部安全基线标准 |  |  |
| 4 | CIS基线标注 |  |  |
| 5 | 报告输出 | √ |  |
| 6 | <font style="color:rgb(31, 35, 40);">Centos7</font> | √ | SSH远程 |
| 7 | Ubuntu | √ | SSH远程 |
| 8 | Windows |  |  |
| 9 | 报告输出 | √ |  |


| 漏洞扫描 | | | |
| :---: | --- | --- | --- |
| 序号 | 功能 | 是否支持 | 备注 |
| 1 | 漏洞（POC）库 | √ | 漏洞信息和POC信息共用一个库 |
| 2 | 扩展POC库 |  | 此项应持续推进。 |
| 3 | CVE库 | √ | cve-search |
| 4 | CVSS库 |  | 用于漏洞库匹配 |
| 5 | CNVD库 |  | 用于漏洞库匹配 |
| 6 | CNNVD库 |  | 用于漏洞库匹配 |
| 7 | CNCVE库 |  | 用于漏洞库匹配 |
| 8 | Bugtraq |  | 用于漏洞库匹配 |
| 9 | 漏洞库匹配 | √ | 目前通过cve-search |
| 10 | POC验证 | √ | 嵌入python解释器 |
| 11 | 插件化扫描 | √ |  |
| 12 | 攻击路径分析 |  | Yang |
| 13 | 多线程 |  | Shi |
| 14 | 报告输出 |  |  |


| 弱口令检测 | | | |
| :---: | --- | --- | --- |
| 序号 | 类型 | 是否支持 | 备注 |
| 1 | 多线程 |  | Huang |
| 2 | SSH | √ | （v1和v2） |
| 3 | HTTP-GET | √ | GET、FORM-POST、FORM-GET、HEAD、Proxy、PROXY |
| 4 | HTTPS-GET | √ | GET、FORM-POST、FORM-GET、HEAD |
| 5 | Telnet | √ |  |
| 6 | FTP | √ |  |
| 7 | RDP | √ |  |
| 8 | VNC | √ |  |
| 9 | SMTP | √ |  |
| 10 | POP3 | √ |  |
| 11 | IMAP | √ |  |
| 12 | LDAP | √ |  |
| 13 | MS-SQL | √ |  |
| 14 | MYSQL | √ |  |
| 15 | Oracle | √ |  |
| 16 | Oracle Listener | √ |  |
| 17 | Oracle SID | √ |  |
| 18 | SMB | √ |  |
| 19 | NCP | √ |  |
| 20 | Rexec | √ |  |
| 21 | Rlogin | √ |  |
| 22 | Rsh | √ |  |
| 23 | SNMP | √ |  |
| 24 | SOCKS5 | √ |  |
| 25 | SMTP枚举 | √ |  |
| 26 | PC-Anywhere | √ |  |
| 27 | Cisco AAA | √ |  |
| 28 | Cisco身份验证 | √ |  |
| 29 | Cisco启用 | √ |  |
| 30 | AFP | √ |  |
| 31 | CVS | √ |  |
| 32 | Firebird | √ |  |
| 33 | ICQ | √ |  |
| 34 | IRC | √ |  |
| 35 | NNTP | √ |  |
| 36 | PCNFS | √ |  |
| 37 | POSTGRES | √ |  |
| 38 | SAP / R3 | √ |  |
| 39 | SIP | √ |  |
| 40 | Subversion | √ |  |
| 41 | Teamspeak（TS2） | √ |  |
| 42 | VMware-Auth | √ |  |
| 43 | XMPP | √ |  |


| 等级保护测评 | | | |
| :---: | --- | --- | --- |
| 序号 | 范围 | 是否支持 | 备注 |
| 1 | 基线检测结果 | √ | 主要是配置核查 |
| 2 | 漏洞扫描结果 |  | 考虑安全风险 |
| 3 | 弱口令检测结果 |  | 考虑安全风险 |
| ~~<font style="color:#DF2A3F;">4</font>~~ | ~~<font style="color:#DF2A3F;">威胁检测结果</font>~~ | ~~<font style="color:#DF2A3F;"></font>~~ | ~~<font style="color:#DF2A3F;"></font>~~ |


| 不在项目研究范围内 | | |
| :---: | --- | --- |
| 序号 | 范围 | 备注 |
| 1 | 对防火墙的主动识别 | 如果需要识别防火墙，或是其安全策略。应采用探针式扫描。 |
| 2 | 对入侵检测系统的主动识别 | 如果需要识别入侵检测系统，或是其<br/>安全策略。应采用探针式扫描。 |
| 3 | 网络协议分析工具：截获并显示网络数据包，分析网络实时流量，捕捉和查看公共网络协议、专用网络协议和工控网络协议 | He |
| 4 | 攻击路径分析 | Yang |
| 5 | 防火墙安全策略冲突 | FU<br/>（需要系统给出识别防火墙规则的方法，比如探针式扫描） |

