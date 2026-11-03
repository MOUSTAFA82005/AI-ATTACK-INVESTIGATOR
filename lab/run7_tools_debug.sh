#!/bin/bash
# Why did dalfox send nothing to DVWA/bWAPP/DVNA, and medusa only 2 requests to DVWA/DVNA?
# Prints the tools' own messages only (not the access logs). Nothing here is captured or sealed.
D=/sealed/run7_tools/debug.txt; : > $D
{
echo "== dalfox version"; dalfox version 2>&1 | head -5
echo "== dalfox cookie flags"; dalfox url --help 2>&1 | grep -i -E "cookie|-C," | head -5
curl -s -c /tmp/j http://nginx-dvwa/login.php > /tmp/l.html
TK=$(grep -o "user_token' value='[^']*" /tmp/l.html | cut -d"'" -f3)
curl -s -b /tmp/j -c /tmp/j -d "username=admin&password=password&Login=Login&user_token=$TK" http://nginx-dvwa/login.php > /dev/null
CK="PHPSESSID=$(awk '/PHPSESSID/{print $7}' /tmp/j); security=low"; echo "dvwa cookie: ${CK:0:20}..."
echo "== dalfox dvwa (first 25 lines)"
timeout 60 dalfox url "http://nginx-dvwa/vulnerabilities/xss_r/?name=test" --cookie "$CK" --no-color 2>&1 | head -25
echo "== medusa dvwa (first 25 lines)"
printf "admin\n" > /tmp/u; printf "aaaa1\nbbbb2\n" > /tmp/p
timeout 60 medusa -h nginx-dvwa -U /tmp/u -P /tmp/p -t 1 -v 6 -M web-form -m FORM:"login.php" -m DENY-SIGNAL:"Login failed" -m FORM-DATA:"post?username=&password=&Login=Login" 2>&1 | head -25
echo "== medusa dvna (first 25 lines)"
timeout 60 medusa -h nginx-dvna -U /tmp/u -P /tmp/p -t 1 -v 6 -M web-form -m FORM:"login" -m DENY-SIGNAL:"Redirecting to /login" -m FORM-DATA:"post?username=&password=" 2>&1 | head -25
} > $D 2>&1
echo "debug written: $(wc -l < $D) lines"
