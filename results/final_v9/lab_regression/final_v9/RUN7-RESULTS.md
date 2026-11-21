# run7 final results

Frozen v8 models, run once, measured as fixed in `PREREGISTRATION.md`. ML = learned pipeline (`model + sessions`), rules = baseline (`rules + rule sessions`). Every number is reported whatever it shows.

## 1. Lab sites (WebGoat = unseen site)

| site | seen in training | log_lines | matched | attacks | normal requests | recall ML | recall rules | FA normal users ML | FA normal users rules | FA in attacker sessions ML | FA in attacker sessions rules | type acc ML | type acc rules | typed requests |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| juiceshop | True | 6321 | 6321 | 2749 | 3572 | 0.999 | 0.983 | 0 | 0 | 37 | 27 | 0.94 | 0.961 | 996 |
| dvwa | True | 5566 | 5553 | 2715 | 2838 | 0.991 | 0.975 | 0 | 0 | 49 | 14 | 0.954 | 0.955 | 999 |
| bwapp | True | 4650 | 4647 | 2697 | 1950 | 0.981 | 0.974 | 0 | 0 | 0 | 24 | 0.964 | 0.978 | 1011 |
| mutillidae | True | 4442 | 4362 | 2622 | 1740 | 0.993 | 0.994 | 0 | 29 | 8 | 133 | 0.939 | 0.96 | 994 |
| dvna | True | 4734 | 4602 | 2597 | 2005 | 0.986 | 0.973 | 0 | 0 | 22 | 22 | 0.961 | 0.973 | 1003 |
| vampi | True | 4625 | 4625 | 2734 | 1891 | 0.992 | 0.68 | 0 | 0 | 37 | 34 | 0.874 | 0.593 | 996 |
| dvga | True | 4674 | 4626 | 2708 | 1918 | 0.962 | 0.693 | 0 | 0 | 5 | 27 | 0.938 | 0.952 | 1020 |
| webgoat | False | 5105 | 4987 | 2716 | 2271 | 0.724 | 0.984 | 0 | 0 | 24 | 24 | 0.956 | 0.976 | 982 |

### Stage and defence

| site | stage requests | stage acc ML | stage acc rules | furthest ML | furthest rules | exploitation found ML/rules | defence action right ML | defence action right rules | defence attackers allowed ML | defence attackers allowed rules | defence normal users blocked ML | defence normal users blocked rules |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| juiceshop | 2747 | 0.998 | 0.918 | 0.956 | 0.856 | 0.92/0.00 (n=13) | 0.993 | 0.93 | 0.0 | 0.0 | 0.0 | 0.0 |
| dvwa | 2691 | 0.968 | 0.635 | 0.956 | 0.411 | 1.00/0.00 (n=255) | 0.993 | 0.913 | 0.0 | 0.0 | 0.0 | 0.0 |
| bwapp | 2645 | 0.985 | 0.733 | 0.989 | 0.611 | 0.98/0.00 (n=130) | 0.993 | 0.903 | 0.0 | 0.0 | 0.0 | 0.0 |
| mutillidae | 2604 | 0.955 | 0.93 | 0.911 | 0.456 | 0.77/0.00 (n=183) | 1.0 | 0.897 | 0.0 | 0.0 | 0.0 | 0.0 |
| dvna | 2561 | 0.977 | 0.929 | 0.978 | 0.344 | 0.91/0.00 (n=182) | 1.0 | 0.897 | 0.0 | 0.0 | 0.0 | 0.0 |
| vampi | 2712 | 1.0 | 0.979 | 1.0 | 0.744 | 1.00/0.00 (n=48) | 0.997 | 0.91 | 0.0 | 0.0 | 0.0 | 0.0 |
| dvga | 2606 | 0.988 | 0.891 | 0.989 | 0.856 | 0.97/0.84 (n=38) | 0.993 | 0.903 | 0.0 | 0.0 | 0.0 | 0.0 |
| webgoat | 1966 | 0.952 | 0.97 | 0.727 | 0.92 | 0.00/1.00 (n=7) | 0.993 | 0.867 | 2.0 | 2.0 | 0.0 | 0.0 |

### Next step (ceiling 0.38 from the generator's random choice)

| site | next campaigns | next top-1 (true order) | next top-3 (true order) | next top-1 (order read) | next top-3 (order read) |
|---|---|---|---|---|---|
| juiceshop | 60.0 | 0.279 | 0.849 | 0.13 | 0.578 |
| dvwa | 60.0 | 0.279 | 0.849 | 0.242 | 0.758 |
| bwapp | 60.0 | 0.279 | 0.849 | 0.183 | 0.646 |
| mutillidae | 60.0 | 0.279 | 0.849 | 0.105 | 0.556 |
| dvna | 60.0 | 0.279 | 0.849 | 0.215 | 0.767 |
| vampi | 60.0 | 0.279 | 0.849 | 0.083 | 0.417 |
| dvga | 60.0 | 0.279 | 0.849 | 0.289 | 0.822 |
| webgoat | 60.0 | 0.279 | 0.849 | 0.245 | 0.81 |

## 2. Sealed tools

medusa ran on bWAPP and Mutillidae only (Amendment 2).

| tool | site | seen site | tool requests | caught ML | caught rules | normal users flagged ML | normal users flagged rules | tool action ML | tool action rules | normal users blocked ML |
|---|---|---|---|---|---|---|---|---|---|---|
| gobuster | juiceshop | True | 2 | 0.0 | 0.0 | 0 | 0 | allow | allow | 0 |
| gobuster | dvwa | True | 4615 | 1.0 | 1.0 | 0 | 0 | rate_limit | rate_limit | 0 |
| gobuster | bwapp | True | 4615 | 1.0 | 1.0 | 0 | 0 | rate_limit | rate_limit | 0 |
| gobuster | mutillidae | True | 4615 | 1.0 | 1.0 | 0 | 29 | rate_limit | rate_limit | 0 |
| gobuster | dvna | True | 4615 | 1.0 | 0.999 | 0 | 0 | rate_limit | rate_limit | 0 |
| gobuster | vampi | True | 4615 | 1.0 | 1.0 | 0 | 0 | rate_limit | rate_limit | 0 |
| gobuster | dvga | True | 4615 | 1.0 | 0.999 | 0 | 0 | rate_limit | rate_limit | 0 |
| feroxbuster | juiceshop | True | 37002 | 1.0 | 1.0 | 0 | 0 | rate_limit | rate_limit | 0 |
| feroxbuster | dvwa | True | 4639 | 1.0 | 1.0 | 0 | 0 | rate_limit | rate_limit | 0 |
| feroxbuster | bwapp | True | 23205 | 1.0 | 1.0 | 0 | 0 | rate_limit | rate_limit | 0 |
| feroxbuster | mutillidae | True | 28512 | 1.0 | 1.0 | 0 | 29 | rate_limit | rate_limit | 0 |
| feroxbuster | dvna | True | 23131 | 1.0 | 1.0 | 0 | 0 | rate_limit | rate_limit | 0 |
| feroxbuster | vampi | True | 9253 | 1.0 | 1.0 | 0 | 0 | rate_limit | rate_limit | 0 |
| feroxbuster | dvga | True | 4654 | 1.0 | 0.998 | 0 | 0 | rate_limit | rate_limit | 0 |
| wfuzz | juiceshop | True | 4616 | 1.0 | 1.0 | 0 | 0 | rate_limit | rate_limit | 0 |
| wfuzz | dvwa | True | 4614 | 1.0 | 1.0 | 0 | 0 | rate_limit | rate_limit | 0 |
| wfuzz | bwapp | True | 4614 | 1.0 | 1.0 | 0 | 0 | rate_limit | rate_limit | 0 |
| wfuzz | mutillidae | True | 4614 | 1.0 | 1.0 | 0 | 29 | rate_limit | rate_limit | 0 |
| wfuzz | dvna | True | 4614 | 1.0 | 0.999 | 0 | 0 | rate_limit | rate_limit | 0 |
| wfuzz | vampi | True | 4614 | 1.0 | 1.0 | 0 | 0 | rate_limit | rate_limit | 0 |
| wfuzz | dvga | True | 4614 | 1.0 | 0.999 | 0 | 0 | rate_limit | rate_limit | 0 |
| dalfox | juiceshop | True | 2 | 0.0 | 0.0 | 0 | 0 | allow | allow | 0 |
| dalfox | dvwa | True | 41 | 0.024 | 0.122 | 0 | 0 | allow | allow | 0 |
| dalfox | bwapp | True | 56 | 0.089 | 0.125 | 0 | 0 | block | rate_limit | 0 |
| dalfox | mutillidae | True | 64 | 0.656 | 0.891 | 0 | 29 | block | block | 0 |
| dalfox | dvna | True | 37 | 0.027 | 0.135 | 0 | 0 | allow | allow | 0 |
| dalfox | vampi | True | 34 | 0.029 | 0.147 | 0 | 0 | allow | allow | 0 |
| dalfox | dvga | True | 57 | 0.053 | 0.088 | 0 | 0 | block | rate_limit | 0 |
| medusa | bwapp | True | 200 | 1.0 | 1.0 | 0 | 0 | rate_limit | block | 0 |
| medusa | mutillidae | True | 200 | 1.0 | 1.0 | 0 | 29 | rate_limit | block | 0 |

Run time: 496 s.
