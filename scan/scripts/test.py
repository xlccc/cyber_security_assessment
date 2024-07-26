#from CVE_2016_3510 import check
#from CVE_2019_10149 import check
from CVE_2017_12615 import check

if __name__ == '__main__':
    
    url = ""
    ip = "192.168.117.100"
    port = 8080

    print(f"Running check with url={url}, ip={ip}, port={port}")

    result = check(url, ip, port)
    if result:
        print(result)
    else:
        print("No vulnerability found.")
