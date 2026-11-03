#!/bin/bash
# run7 sealed tools, second pass: fix the 5 failed runs.
#  - dalfox dvwa/bwapp/dvna: first pass used --cookie; the flag is --cookies. Re-run with cookies.
#  - medusa dvwa/dvna: login returns 302 (both success and failure redirect), so medusa's web-form
#    module cannot accept or read the response and aborts. medusa is skipped on these two sites,
#    same as on the JSON-login sites. The 2 bogus files are removed.
# Replaces only those files, then re-hashes ALL tool logs. Output files stay SEALED (never opened).
set -u
OUT=/sealed/run7_tools; cd $OUT
ME=$(hostname -I | awk '{print $1}'); echo "== second pass, tools container IP: $ME $(date -u +%FT%TZ)" | tee -a runs.txt

logof() { [ "$1" = juiceshop ] && echo /lab/logs/access.log || echo /lab/logs/$1_access.log; }
cap() {   # cap <tool> <site> <command...>: the new log lines this container produced
  local tool=$1 site=$2; shift 2; local LOG=$(logof $site) f=tool_${tool}_${site}.log
  local a=$(stat -c %s $LOG); echo "== $site $tool start $(date -u +%FT%TZ)" >> runs.txt
  timeout 600 "$@" > /dev/null 2>&1; sleep 2
  tail -c +$((a+1)) $LOG | awk -v ip="$ME" '$1==ip' > $f
  echo "   $site $tool end $(date -u +%FT%TZ) lines $(wc -l < $f)" | tee -a runs.txt
}

# remove the 5 bad files
rm -f tool_dalfox_dvwa.log tool_dalfox_bwapp.log tool_dalfox_dvna.log
rm -f tool_medusa_dvwa.log tool_medusa_dvna.log
echo "   removed 3 dalfox (bad flag) + 2 medusa (302 login, skipped)" | tee -a runs.txt

# logins again to get sessions for the cookie dalfox runs
J=/tmp/jar
curl -s -c $J.dvwa http://nginx-dvwa/login.php > /tmp/l.html
TK=$(grep -o "user_token' value='[^']*" /tmp/l.html | cut -d"'" -f3)
curl -s -b $J.dvwa -c $J.dvwa -d "username=admin&password=password&Login=Login&user_token=$TK" http://nginx-dvwa/login.php > /dev/null
CK_dvwa="PHPSESSID=$(awk '/PHPSESSID/{print $7}' $J.dvwa); security=low"
curl -s -c $J.bwapp -d "login=bee&password=bug&security_level=0&form=submit" http://nginx-bwapp/login.php > /dev/null
CK_bwapp="PHPSESSID=$(awk '/PHPSESSID/{print $7}' $J.bwapp); security_level=0"
curl -s -c $J.dvna -d "name=Lab+r7&username=r7tool&email=r7%40example-lab.test&password=Rq7xLab551&cpassword=Rq7xLab551" http://nginx-dvna/register > /dev/null
curl -s -b $J.dvna -c $J.dvna -d "username=r7tool&password=Rq7xLab551" http://nginx-dvna/login > /dev/null
CK_dvna="connect.sid=$(awk '/connect.sid/{print $7}' $J.dvna)"

cap dalfox dvwa  dalfox url "http://nginx-dvwa/vulnerabilities/xss_r/?name=test" --cookies "$CK_dvwa" --silence
cap dalfox bwapp dalfox url "http://nginx-bwapp/xss_get.php?firstname=a&lastname=b&form=submit" --cookies "$CK_bwapp" --silence
cap dalfox dvna  dalfox url "http://nginx-dvna/app/usersearch" -d "login=a" --cookies "$CK_dvna" --silence

sha256sum tool_*.log | awk '{print toupper($1) "  " $2}' > hashes.txt
echo "second pass done. files: $(ls tool_*.log | wc -l)   hashes: $(wc -l < hashes.txt)" | tee -a runs.txt
