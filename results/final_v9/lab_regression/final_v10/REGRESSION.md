# Lab regression: final_v10

Detector: `C:\Users\ms182\Downloads\AI PROJECT\AI-ATTACK-INVESTIGATOR\models\detector.joblib`, context: `models/context.joblib`, type: `models/attack_type.joblib`, stage: `models/stage.joblib`. Dev data (run7 is opened). run7 = frozen v8 numbers.

## Lab sites

| site | recall ML run7 | recall ML now | FA normal users ML run7 | FA normal users ML now | FA in attacker sessions ML run7 | FA in attacker sessions ML now | type acc ML run7 | type acc ML now | defence action right ML run7 | defence action right ML now |
|---|---|---|---|---|---|---|---|---|---|---|
| juiceshop | 0.984 | 1.0 | 0 | 0 | 19 | 2 | 0.941 | 0.94 | 0.993 | 1.0 |
| dvwa | 0.988 | 0.995 | 0 | 0 | 26 | 0 | 0.944 | 0.954 | 0.993 | 1.0 |
| bwapp | 0.97 | 0.992 | 0 | 0 | 0 | 0 | 0.948 | 0.963 | 0.993 | 1.0 |
| mutillidae | 0.996 | 0.996 | 0 | 0 | 2 | 2 | 0.957 | 0.939 | 0.993 | 0.991 |
| dvna | 0.991 | 0.987 | 0 | 0 | 22 | 0 | 0.972 | 0.961 | 0.993 | 0.998 |
| vampi | 0.989 | 0.989 | 0 | 0 | 36 | 13 | 0.657 | 0.873 | 0.997 | 0.991 |
| dvga | 0.971 | 0.994 | 0 | 0 | 5 | 10 | 0.946 | 0.938 | 0.993 | 0.993 |
| webgoat | 0.693 | 0.728 | 0 | 0 | 24 | 0 | 0.962 | 0.956 | 0.993 | 0.939 |

### Stage

| site | stage acc ML run7 | stage acc ML now | furthest ML run7 | furthest ML now |
|---|---|---|---|---|
| juiceshop | 0.999 | 0.999 | 0.978 | 0.987 |
| dvwa | 0.969 | 0.969 | 0.956 | 0.986 |
| bwapp | 0.985 | 0.985 | 0.989 | 0.975 |
| mutillidae | 0.964 | 0.958 | 0.878 | 0.908 |
| dvna | 0.976 | 0.975 | 0.978 | 0.986 |
| vampi | 1.0 | 1.0 | 0.989 | 1.0 |
| dvga | 0.989 | 0.99 | 1.0 | 0.996 |
| webgoat | 0.985 | 0.977 | 0.83 | 0.956 |

## Recall by attack type (ML)

| site | attack_type | model + sessions run7 | model + sessions now | drop |
|---|---|---|---|---|
| juiceshop | bruteforce | 1.0 | 1.0 | 0.0 |
| juiceshop | cmdi | 0.994 | 1.0 | -0.006 |
| juiceshop | enum | 0.946 | 1.0 | -0.054 |
| juiceshop | ldap | 1.0 | 1.0 | 0.0 |
| juiceshop | log4shell | 1.0 | 1.0 | 0.0 |
| juiceshop | nosql | 0.833 | 0.917 | -0.084 |
| juiceshop | scan | 1.0 | 1.0 | 0.0 |
| juiceshop | sqli | 1.0 | 1.0 | 0.0 |
| juiceshop | ssrf | 1.0 | 1.0 | 0.0 |
| juiceshop | ssti | 1.0 | 1.0 | 0.0 |
| juiceshop | traversal | 1.0 | 1.0 | 0.0 |
| juiceshop | xss | 1.0 | 1.0 | 0.0 |
| juiceshop | xxe | 1.0 | 1.0 | 0.0 |
| dvwa | bruteforce | 1.0 | 1.0 | 0.0 |
| dvwa | cmdi | 0.99 | 0.99 | 0.0 |
| dvwa | enum | 1.0 | 1.0 | 0.0 |
| dvwa | ldap | 1.0 | 1.0 | 0.0 |
| dvwa | log4shell | 1.0 | 1.0 | 0.0 |
| dvwa | nosql | 1.0 | 1.0 | 0.0 |
| dvwa | scan | 0.96 | 0.986 | -0.026 |
| dvwa | sqli | 1.0 | 1.0 | 0.0 |
| dvwa | ssrf | 0.875 | 0.875 | 0.0 |
| dvwa | ssti | 1.0 | 1.0 | 0.0 |
| dvwa | traversal | 1.0 | 1.0 | 0.0 |
| dvwa | xss | 1.0 | 1.0 | 0.0 |
| dvwa | xxe | 1.0 | 1.0 | 0.0 |
| bwapp | bruteforce | 1.0 | 1.0 | 0.0 |
| bwapp | cmdi | 1.0 | 1.0 | 0.0 |
| bwapp | enum | 1.0 | 1.0 | 0.0 |
| bwapp | ldap | 1.0 | 1.0 | 0.0 |
| bwapp | log4shell | 1.0 | 1.0 | 0.0 |
| bwapp | nosql | 1.0 | 0.909 | 0.091 |
| bwapp | scan | 0.887 | 0.972 | -0.085 |
| bwapp | sqli | 1.0 | 1.0 | 0.0 |
| bwapp | ssrf | 0.833 | 0.833 | 0.0 |
| bwapp | ssti | 1.0 | 1.0 | 0.0 |
| bwapp | traversal | 1.0 | 1.0 | 0.0 |
| bwapp | xss | 1.0 | 1.0 | 0.0 |
| bwapp | xxe | 1.0 | 1.0 | 0.0 |
| mutillidae | bruteforce | 1.0 | 1.0 | 0.0 |
| mutillidae | cmdi | 0.994 | 0.994 | 0.0 |
| mutillidae | ldap | 1.0 | 1.0 | 0.0 |
| mutillidae | log4shell | 1.0 | 1.0 | 0.0 |
| mutillidae | nosql | 1.0 | 1.0 | 0.0 |
| mutillidae | scan | 0.998 | 0.999 | -0.001 |
| mutillidae | sqli | 1.0 | 1.0 | 0.0 |
| mutillidae | ssrf | 0.615 | 0.615 | 0.0 |
| mutillidae | ssti | 0.952 | 0.952 | 0.0 |
| mutillidae | traversal | 0.996 | 0.996 | 0.0 |
| mutillidae | xss | 1.0 | 1.0 | 0.0 |
| mutillidae | xxe | 1.0 | 1.0 | 0.0 |
| dvna | bruteforce | 1.0 | 1.0 | 0.0 |
| dvna | cmdi | 0.896 | 0.844 | 0.052 |
| dvna | ldap | 1.0 | 1.0 | 0.0 |
| dvna | log4shell | 1.0 | 1.0 | 0.0 |
| dvna | nosql | 1.0 | 1.0 | 0.0 |
| dvna | scan | 1.0 | 1.0 | 0.0 |
| dvna | sqli | 1.0 | 1.0 | 0.0 |
| dvna | ssrf | 0.812 | 0.812 | 0.0 |
| dvna | ssti | 0.966 | 0.897 | 0.069 |
| dvna | traversal | 1.0 | 1.0 | 0.0 |
| dvna | xss | 1.0 | 1.0 | 0.0 |
| dvna | xxe | 0.75 | 0.75 | 0.0 |
| vampi | bruteforce | 1.0 | 0.939 | 0.061 |
| vampi | cmdi | 0.968 | 0.924 | 0.044 |
| vampi | enum | 1.0 | 1.0 | 0.0 |
| vampi | ldap | 1.0 | 0.895 | 0.105 |
| vampi | log4shell | 1.0 | 1.0 | 0.0 |
| vampi | nosql | 0.909 | 0.818 | 0.091 |
| vampi | scan | 0.969 | 1.0 | -0.031 |
| vampi | sqli | 1.0 | 1.0 | 0.0 |
| vampi | ssrf | 0.75 | 0.75 | 0.0 |
| vampi | ssti | 1.0 | 1.0 | 0.0 |
| vampi | traversal | 1.0 | 1.0 | 0.0 |
| vampi | xss | 1.0 | 1.0 | 0.0 |
| vampi | xxe | 0.957 | 0.957 | 0.0 |
| dvga | bruteforce | 1.0 | 1.0 | 0.0 |
| dvga | cmdi | 0.982 | 0.982 | 0.0 |
| dvga | enum | 0.964 | 1.0 | -0.036 |
| dvga | ldap | 1.0 | 1.0 | 0.0 |
| dvga | log4shell | 1.0 | 1.0 | 0.0 |
| dvga | nosql | 1.0 | 0.933 | 0.067 |
| dvga | scan | 0.939 | 0.989 | -0.05 |
| dvga | sqli | 1.0 | 1.0 | 0.0 |
| dvga | ssrf | 0.875 | 0.875 | 0.0 |
| dvga | ssti | 1.0 | 1.0 | 0.0 |
| dvga | traversal | 0.99 | 0.99 | 0.0 |
| dvga | xss | 1.0 | 1.0 | 0.0 |
| dvga | xxe | 1.0 | 1.0 | 0.0 |
| webgoat | bruteforce | 1.0 | 1.0 | 0.0 |
| webgoat | cmdi | 0.993 | 0.953 | 0.04 |
| webgoat | enum | 0.0 | 0.034 | -0.034 |
| webgoat | ldap | 1.0 | 1.0 | 0.0 |
| webgoat | log4shell | 1.0 | 1.0 | 0.0 |
| webgoat | nosql | 1.0 | 1.0 | 0.0 |
| webgoat | scan | 0.896 | 1.0 | -0.104 |
| webgoat | sqli | 1.0 | 1.0 | 0.0 |
| webgoat | ssrf | 0.75 | 0.75 | 0.0 |
| webgoat | ssti | 1.0 | 0.8 | 0.2 |
| webgoat | traversal | 1.0 | 1.0 | 0.0 |
| webgoat | xss | 1.0 | 1.0 | 0.0 |
| webgoat | xxe | 1.0 | 1.0 | 0.0 |

Drops of 0.05 or more:

| site | attack_type | model + sessions run7 | model + sessions now | drop |
|---|---|---|---|---|
| bwapp | nosql | 1.0 | 0.909 | 0.091 |
| dvna | cmdi | 0.896 | 0.844 | 0.052 |
| dvna | ssti | 0.966 | 0.897 | 0.069 |
| vampi | bruteforce | 1.0 | 0.939 | 0.061 |
| vampi | ldap | 1.0 | 0.895 | 0.105 |
| vampi | nosql | 0.909 | 0.818 | 0.091 |
| dvga | nosql | 1.0 | 0.933 | 0.067 |
| webgoat | ssti | 1.0 | 0.8 | 0.2 |

## Brute force (must stay caught by sessions)

| site | attack_type | model + sessions run7 | model + sessions now | drop |
|---|---|---|---|---|
| juiceshop | bruteforce | 1.0 | 1.0 | 0.0 |
| dvwa | bruteforce | 1.0 | 1.0 | 0.0 |
| bwapp | bruteforce | 1.0 | 1.0 | 0.0 |
| mutillidae | bruteforce | 1.0 | 1.0 | 0.0 |
| dvna | bruteforce | 1.0 | 1.0 | 0.0 |
| vampi | bruteforce | 1.0 | 0.939 | 0.061 |
| dvga | bruteforce | 1.0 | 1.0 | 0.0 |
| webgoat | bruteforce | 1.0 | 1.0 | 0.0 |

## Tools

| tool | site | caught ML run7 | caught ML now | normal users flagged ML run7 | normal users flagged ML now |
|---|---|---|---|---|---|
| gobuster | juiceshop | 0.5 | 0.0 | 0 | 0 |
| gobuster | dvwa | 1.0 | 1.0 | 0 | 0 |
| gobuster | bwapp | 1.0 | 1.0 | 0 | 0 |
| gobuster | mutillidae | 1.0 | 1.0 | 0 | 0 |
| gobuster | dvna | 1.0 | 1.0 | 0 | 0 |
| gobuster | vampi | 1.0 | 1.0 | 0 | 0 |
| gobuster | dvga | 1.0 | 1.0 | 0 | 0 |
| feroxbuster | juiceshop | 1.0 | 1.0 | 0 | 0 |
| feroxbuster | dvwa | 1.0 | 1.0 | 0 | 0 |
| feroxbuster | bwapp | 1.0 | 1.0 | 0 | 0 |
| feroxbuster | mutillidae | 1.0 | 1.0 | 0 | 0 |
| feroxbuster | dvna | 1.0 | 1.0 | 0 | 0 |
| feroxbuster | vampi | 1.0 | 1.0 | 0 | 0 |
| feroxbuster | dvga | 1.0 | 1.0 | 0 | 0 |
| wfuzz | juiceshop | 1.0 | 1.0 | 0 | 0 |
| wfuzz | dvwa | 1.0 | 1.0 | 0 | 0 |
| wfuzz | bwapp | 1.0 | 1.0 | 0 | 0 |
| wfuzz | mutillidae | 1.0 | 1.0 | 0 | 0 |
| wfuzz | dvna | 1.0 | 1.0 | 0 | 0 |
| wfuzz | vampi | 1.0 | 1.0 | 0 | 0 |
| wfuzz | dvga | 1.0 | 1.0 | 0 | 0 |
| dalfox | juiceshop | 0.0 | 0.0 | 0 | 0 |
| dalfox | dvwa | 0.024 | 0.024 | 0 | 0 |
| dalfox | bwapp | 0.089 | 0.089 | 0 | 0 |
| dalfox | mutillidae | 0.078 | 0.609 | 0 | 0 |
| dalfox | dvna | 0.027 | 0.027 | 0 | 0 |
| dalfox | vampi | 0.029 | 0.029 | 0 | 0 |
| dalfox | dvga | 0.07 | 0.053 | 0 | 0 |
| medusa | bwapp | 1.0 | 1.0 | 0 | 0 |
| medusa | mutillidae | 1.0 | 1.0 | 0 | 0 |
