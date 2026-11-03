#!/bin/bash
# run7 sealed tools: gobuster, feroxbuster, wfuzz, dalfox, medusa against our own lab sites only
# (Docker network lab_default, nothing outside). Detection / guessing only, fake passwords.
# None of these tools was ever run in this project before. Output files are SEALED: they are
# hashed here and must not be opened. Run inside a Kali container, see the step in the thread.
set -u
OUT=/sealed/run7_tools; mkdir -p $OUT; cd $OUT
ME=$(hostname -I | awk '{print $1}'); echo "tools container IP: $ME" | tee -a runs.txt
W=/usr/share/dirb/wordlists/common.txt
printf "admin\nuser\ntest\nbee\nroot\n" > users.txt
for i in $(seq 1 40); do tr -dc 'a-z0-9' < /dev/urandom | head -c 10; echo; done > pass.txt   # fake

declare -A HOST=( [juiceshop]=nginx [dvwa]=nginx-dvwa [bwapp]=nginx-bwapp [mutillidae]=nginx-mutillidae
                  [dvna]=nginx-dvna [vampi]=nginx-vampi [dvga]=nginx-dvga )
logof() { [ "$1" = juiceshop ] && echo /lab/logs/access.log || echo /lab/logs/$1_access.log; }

cap() {   # cap <tool> <site> <command...>: the new log lines this container produced
  local tool=$1 site=$2; shift 2; local LOG=$(logof $site) f=tool_${tool}_${site}.log
  local a=$(stat -c %s $LOG); echo "== $site $tool start $(date -u +%FT%TZ)" >> runs.txt
  timeout 600 "$@" > /dev/null 2>&1; sleep 2
  tail -c +$((a+1)) $LOG | awk -v ip="$ME" '$1==ip' > $f
  echo "   $site $tool end $(date -u +%FT%TZ) lines $(wc -l < $f)" | tee -a runs.txt
}

# logins (fake account for DVNA; lab default accounts elsewhere) to give tools a session
J=/tmp/jar; CK_dvwa=""; CK_bwapp=""; CK_dvna=""
curl -s -c $J.dvwa http://nginx-dvwa/login.php > /tmp/l.html
TK=$(grep -o "user_token' value='[^']*" /tmp/l.html | cut -d"'" -f3)
curl -s -b $J.dvwa -c $J.dvwa -d "username=admin&password=password&Login=Login&user_token=$TK" http://nginx-dvwa/login.php > /dev/null
CK_dvwa="PHPSESSID=$(awk '/PHPSESSID/{print $7}' $J.dvwa); security=low"
curl -s -c $J.bwapp -d "login=bee&password=bug&security_level=0&form=submit" http://nginx-bwapp/login.php > /dev/null
CK_bwapp="PHPSESSID=$(awk '/PHPSESSID/{print $7}' $J.bwapp); security_level=0"
curl -s -c $J.dvna -d "name=Lab+r7&username=r7tool&email=r7%40example-lab.test&password=Rq7xLab551&cpassword=Rq7xLab551" http://nginx-dvna/register > /dev/null
curl -s -b $J.dvna -c $J.dvna -d "username=r7tool&password=Rq7xLab551" http://nginx-dvna/login > /dev/null
CK_dvna="connect.sid=$(awk '/connect.sid/{print $7}' $J.dvna)"

for site in juiceshop dvwa bwapp mutillidae dvna vampi dvga; do
  H=${HOST[$site]}; B=http://$H
  cap gobuster $site gobuster dir -u $B/ -w $W -t 10 -q --no-error
  cap feroxbuster $site feroxbuster -u $B/ -w $W -t 10 --time-limit 8m -q --no-state
  cap wfuzz $site wfuzz -w $W --hc 404 -t 10 $B/FUZZ
  case $site in
    juiceshop)  cap dalfox $site dalfox url "$B/rest/products/search?q=apple" --silence ;;
    dvwa)       cap dalfox $site dalfox url "$B/vulnerabilities/xss_r/?name=test" --cookie "$CK_dvwa" --silence ;;
    bwapp)      cap dalfox $site dalfox url "$B/xss_get.php?firstname=a&lastname=b&form=submit" --cookie "$CK_bwapp" --silence ;;
    mutillidae) cap dalfox $site dalfox url "$B/index.php?page=user-info.php&username=a&password=b&user-info-php-submit-button=View+Account+Details" --silence ;;
    dvna)       cap dalfox $site dalfox url "$B/app/usersearch" -d "login=a" --cookie "$CK_dvna" --silence ;;
    vampi)      cap dalfox $site dalfox url "$B/users/v1/name1" --silence ;;
    dvga)       cap dalfox $site dalfox url "$B/graphiql?query=a" --silence ;;
  esac
  # medusa's web-form module sends form fields only: run on the sites whose login is a form
  case $site in
    dvwa)       cap medusa $site medusa -h $H -U users.txt -P pass.txt -t 2 -M web-form -m FORM:"login.php" -m DENY-SIGNAL:"Login failed" -m FORM-DATA:"post?username=&password=&Login=Login" ;;
    bwapp)      cap medusa $site medusa -h $H -U users.txt -P pass.txt -t 2 -M web-form -m FORM:"login.php" -m DENY-SIGNAL:"Invalid credentials" -m FORM-DATA:"post?login=&password=&security_level=0&form=submit" ;;
    mutillidae) cap medusa $site medusa -h $H -U users.txt -P pass.txt -t 2 -M web-form -m FORM:"index.php?page=login.php" -m DENY-SIGNAL:"incorrect" -m FORM-DATA:"post?username=&password=&login-php-submit-button=Login" ;;
    dvna)       cap medusa $site medusa -h $H -U users.txt -P pass.txt -t 2 -M web-form -m FORM:"login" -m DENY-SIGNAL:"Redirecting to /login" -m FORM-DATA:"post?username=&password=" ;;
    *)          echo "   $site medusa skipped: JSON login, medusa web-form sends form fields only" | tee -a runs.txt ;;
  esac
done
sha256sum tool_*.log | awk '{print toupper($1) "  " $2}' > hashes.txt
echo "files: $(ls tool_*.log | wc -l)   hashes: $(wc -l < hashes.txt)"
