"""Generate fresh WeChat login QR code from vmq-itchat container."""
import re
import subprocess
import time

import qrcode

# Get URL from logs (container already running)
result = subprocess.run(["sudo", "docker", "logs", "vmq-itchat"], capture_output=True, text=True)
match = re.search(r"login\.weixin\.qq\.com/l/[A-Za-z0-9=/_]+", result.stdout)
if not match:
    # Restart and wait for fresh QR
    subprocess.run(["sudo", "docker", "restart", "vmq-itchat"], capture_output=True)
    time.sleep(12)
    result = subprocess.run(["sudo", "docker", "logs", "vmq-itchat"], capture_output=True, text=True)
    match = re.search(r"login\.weixin\.qq\.com/l/[A-Za-z0-9=/_]+", result.stdout)

if not match:
    print("ERROR: No WeChat login URL found")
    raise SystemExit(1)

wx_url = "https://" + match.group(0)
print(f"URL: {wx_url}")

img = qrcode.make(wx_url)
img.save("app/static/img/wx_login_qr.png")
print("QR saved")
