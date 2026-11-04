# v9 sealed test

Run once at tag v9.0-final-test. Rules, frozen v8 and v9 on the same converted rows.

## 1. Glastopf honeypot, sealed months (headline: share of IPs flagged, Amendment 1)

| detector | requests | requests flagged | IPs | IPs flagged |
|---|---|---|---|---|
| payload rules | 2865 | 0.036 | 487 | 0.099 |
| rules + rule sessions | 2865 | 0.456 | 487 | 0.158 |
| v8 payload model | 2865 | 0.345 | 487 | 0.218 |
| v8 model + sessions | 2865 | 0.666 | 487 | 0.22 |
| v9 payload model | 2865 | 0.042 | 487 | 0.115 |
| v9 model + sessions | 2865 | 0.631 | 487 | 0.164 |
| v9 payload @0.8 (sensitivity) | 2865 | 0.042 | 487 | 0.115 |

## 2. ModSec-WP (whole source unseen)

| detector | recall bruteforce (n=7568) | recall fileinclusion (n=6290) | recall rce (n=4172) | recall sqli (n=69631) | recall xss (n=8625) | false alarms on normal (n=12597) |
|---|---|---|---|---|---|---|
| payload rules | 0.064 | 0.92 | 0.548 | 0.948 | 0.947 | 0.1279 |
| rules + rule sessions | 0.064 | 0.976 | 0.625 | 0.957 | 0.947 | 0.2151 |
| v8 payload model | 0.064 | 0.989 | 0.907 | 0.988 | 0.968 | 0.4014 |
| v8 model + sessions | 1.0 | 0.997 | 0.995 | 1.0 | 0.996 | 0.9679 |
| v9 payload model | 1.0 | 0.952 | 0.683 | 0.984 | 0.951 | 0.1276 |
| v9 model + sessions | 1.0 | 0.966 | 0.769 | 0.993 | 0.951 | 0.5847 |
| v9 payload @0.8 (sensitivity) | 1.0 | 0.938 | 0.645 | 0.983 | 0.95 | 0.1276 |

### Attack type on flagged requests (right types per class fixed in Amendment 6)

| class | payload rules | v8 model | v9 model |
|---|---|---|---|
| fileinclusion | 0.958 | 0.94 | 0.914 |
| rce | 0.771 | 0.625 | 0.683 |
| sqli | 0.966 | 0.99 | 0.993 |
| xss | 0.998 | 0.968 | 0.988 |

## 3. Real normal traffic: share of requests flagged = false-alarm rate

| log | detector | normal requests | flagged (false alarms) |
|---|---|---|---|
| zanbil lines 10,000,001-10,200,000 | payload rules | 200000 | 9e-05 |
| zanbil lines 10,000,001-10,200,000 | rules + rule sessions | 200000 | 0.00342 |
| zanbil lines 10,000,001-10,200,000 | v8 payload model | 200000 | 0.00013 |
| zanbil lines 10,000,001-10,200,000 | v8 model + sessions | 200000 | 0.00018 |
| zanbil lines 10,000,001-10,200,000 | v9 payload model | 200000 | 6e-05 |
| zanbil lines 10,000,001-10,200,000 | v9 model + sessions | 200000 | 0.00012 |
| zanbil lines 10,000,001-10,200,000 | v9 payload @0.8 (sensitivity) | 200000 | 5e-05 |
| Indonesian sites, benign part | payload rules | 3055949 | 0.00039 |
| Indonesian sites, benign part | rules + rule sessions | 3055949 | 0.60372 |
| Indonesian sites, benign part | v8 payload model | 3055949 | 0.46584 |
| Indonesian sites, benign part | v8 model + sessions | 3055949 | 0.871 |
| Indonesian sites, benign part | v9 payload model | 3055949 | 0.00043 |
| Indonesian sites, benign part | v9 model + sessions | 3055949 | 0.58203 |
| Indonesian sites, benign part | v9 payload @0.8 (sensitivity) | 3055949 | 0.00037 |
|   organization-x | payload rules | 199455 | 0.00284 |
|   organization-x | rules + rule sessions | 199455 | 0.70938 |
|   organization-x | v8 payload model | 199455 | 0.00299 |
|   organization-x | v8 model + sessions | 199455 | 0.99993 |
|   organization-x | v9 payload model | 199455 | 0.00143 |
|   organization-x | v9 model + sessions | 199455 | 0.08934 |
|   organization-x | v9 payload @0.8 (sensitivity) | 199455 | 0.00132 |
|   organization-y | payload rules | 2856494 | 0.00022 |
|   organization-y | rules + rule sessions | 2856494 | 0.59634 |
|   organization-y | v8 payload model | 2856494 | 0.49816 |
|   organization-y | v8 model + sessions | 2856494 | 0.862 |
|   organization-y | v9 payload model | 2856494 | 0.00036 |
|   organization-y | v9 model + sessions | 2856494 | 0.61643 |
|   organization-y | v9 payload @0.8 (sensitivity) | 2856494 | 0.0003 |

### Indonesian lines matched by their attack rules (extra, not preregistered)

| label (their YAML rule) | requests | payload rules | rules + rule sessions | v8 payload model | v8 model + sessions | v9 payload model | v9 model + sessions | v9 payload @0.8 (sensitivity) |
|---|---|---|---|---|---|---|---|---|
| api_call | 6 | 0.0 | 1.0 | 0.0 | 1.0 | 0.0 | 1.0 | 0.0 |
| cross_site_scripting | 16 | 0.812 | 1.0 | 1.0 | 1.0 | 0.875 | 1.0 | 0.875 |
| dir_scan | 44 | 0.0 | 0.955 | 0.045 | 1.0 | 0.0 | 0.955 | 0.0 |
| dir_scan_go | 136 | 0.0 | 1.0 | 0.0 | 1.0 | 0.0 | 1.0 | 0.0 |
| file_inclusion | 1581 | 0.026 | 0.545 | 0.085 | 0.958 | 0.027 | 0.465 | 0.027 |
| path_traversal | 7 | 0.0 | 1.0 | 0.0 | 1.0 | 0.0 | 1.0 | 0.0 |
| rce_java | 7 | 0.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| rce_read_file | 135 | 0.896 | 0.985 | 0.963 | 1.0 | 0.785 | 0.993 | 0.785 |
| rce_shell | 53 | 0.774 | 0.887 | 0.774 | 1.0 | 0.755 | 0.925 | 0.755 |
| rce_sysinfo | 4 | 0.5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| remote_code | 75 | 0.44 | 1.0 | 0.64 | 1.0 | 0.533 | 1.0 | 0.533 |
| shell_execution | 7 | 0.0 | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 0.0 |
| sql_injection_attempt | 90 | 0.922 | 0.978 | 0.933 | 1.0 | 0.933 | 0.956 | 0.933 |

## 4. SR-BH sealed days, per request (Amendments 2-3: false alarms; agreement with CRS)

| detector | normal requests | flagged | CRS attacks | recall vs CRS |
|---|---|---|---|---|
| payload rules | 311759 | 0.0 | 1 | 0.0 |
| v8 payload model | 311759 | 0.00563 | 1 | 0.0 |
| v9 payload model | 311759 | 0.0 | 1 | 0.0 |
| v9 payload @0.8 (sensitivity) | 311759 | 0.0 | 1 | 0.0 |

## 5. ModSecurity 30-day production log (secondary: WAF-logged requests flagged)

| detector | requests (all WAF-logged) | share flagged |
|---|---|---|
| payload rules | 151845 | 0.043 |
| rules + rule sessions | 151845 | 0.379 |
| v8 payload model | 151845 | 0.339 |
| v8 model + sessions | 151845 | 0.618 |
| v9 payload model | 151845 | 0.066 |
| v9 model + sessions | 151845 | 0.498 |
| v9 payload @0.8 (sensitivity) | 151845 | 0.064 |
