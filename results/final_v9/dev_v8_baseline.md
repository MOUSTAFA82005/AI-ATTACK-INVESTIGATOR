# v8 (frozen) and rules on the v9 DEV data

DEV only. Not a test result: v9 will be trained and tuned on this data.

## SR-BH dev (17-24 Jul 2020), labels = ModSecurity CRS

| detector | attacks | caught | recall vs CRS | normals | normals flagged | false-alarm rate | precision vs CRS |
|---|---|---|---|---|---|---|---|
| ML (v8) | 382619 | 382613 | 1.0 | 213434 | 164637 | 0.7714 | 0.699 |
| rules | 382619 | 358254 | 0.936 | 213434 | 184877 | 0.8662 | 0.66 |

| family (CRS) | requests | recall ML (v8) | recall rules |
|---|---|---|---|
| sqli | 250311 | 1.0 | 0.965 |
| spoofing | 56145 | 1.0 | 0.888 |
| protocol | 33457 | 1.0 | 0.811 |
| traversal | 20992 | 1.0 | 0.961 |
| code_injection | 15826 | 1.0 | 0.952 |
| cmdi | 7483 | 1.0 | 0.877 |
| scan | 2718 | 1.0 | 0.993 |
| input_manipulation | 2272 | 1.0 | 0.236 |
| bruteforce | 1847 | 1.0 | 0.993 |

### Where the flagged normal requests come from

| group | requests | flagged model only (v8) | flagged model + sessions (v8) | flagged payload rules | flagged rules + sessions |
|---|---|---|---|---|---|
| normal requests from IPs that also attacked (same day) | 162720 | 0.3541 | 0.9924 | 0.0026 | 0.8364 |
| normal requests from IPs that never attacked (same day) | 50714 | 0.0622 | 0.0622 | 0.0 | 0.962 |

Sources (day, IP): 8 in total, 3 sent at least one CRS-labelled attack.

## Glastopf honeypot dev (2014-09 .. 2015-03), all traffic hits a honeypot

| detector | requests | requests flagged | IPs | IPs flagged (headline) |
|---|---|---|---|---|
| ML (v8) | 4334 | 0.481 | 882 | 0.207 |
| rules | 4334 | 0.42 | 882 | 0.132 |

| pattern | requests | flagged ML (v8) | flagged rules |
|---|---|---|---|
| unknown | 3669 | 0.549 | 0.485 |
| head | 299 | 0.08 | 0.0 |
| tomcat_manager | 296 | 0.003 | 0.0 |
| login | 37 | 1.0 | 1.0 |
| robots | 12 | 0.0 | 0.0 |
| style_css | 9 | 0.0 | 0.0 |
| lfi | 5 | 0.8 | 0.2 |
| phpinfo | 3 | 0.333 | 0.0 |
| rfi | 2 | 0.5 | 0.0 |
| file_server | 1 | 1.0 | 0.0 |
| comments | 1 | 0.0 | 0.0 |
