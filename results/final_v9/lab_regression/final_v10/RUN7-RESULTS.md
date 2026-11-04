# run7 final results

Frozen v8 models, run once, measured as fixed in `PREREGISTRATION.md`. ML = learned pipeline (`model + sessions`), rules = baseline (`rules + rule sessions`). Every number is reported whatever it shows.

## 1. Lab sites (WebGoat = unseen site)

| site | seen in training | log_lines | matched | attacks | normal requests | recall ML | recall rules | FA normal users ML | FA normal users rules | FA in attacker sessions ML | FA in attacker sessions rules | type acc ML | type acc rules | typed requests |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| juiceshop | True | 6321 | 6321 | 2749 | 3572 | 1.0 | 0.981 | 0 | 0 | 2 | 1 | 0.94 | 0.96 | 997 |
| dvwa | True | 5566 | 5553 | 2715 | 2838 | 0.995 | 0.975 | 0 | 0 | 0 | 0 | 0.954 | 0.955 | 999 |
| bwapp | True | 4650 | 4647 | 2697 | 1950 | 0.992 | 0.97 | 0 | 0 | 0 | 0 | 0.963 | 0.977 | 1012 |
| mutillidae | True | 4442 | 4362 | 2622 | 1740 | 0.996 | 0.994 | 0 | 29 | 2 | 114 | 0.939 | 0.96 | 994 |
| dvna | True | 4734 | 4602 | 2597 | 2005 | 0.987 | 0.972 | 0 | 0 | 0 | 0 | 0.961 | 0.973 | 1005 |
| vampi | True | 4625 | 4625 | 2734 | 1891 | 0.989 | 0.598 | 0 | 0 | 13 | 16 | 0.873 | 0.592 | 998 |
| dvga | True | 4674 | 4626 | 2708 | 1918 | 0.994 | 0.692 | 0 | 0 | 10 | 3 | 0.938 | 0.952 | 1020 |
| webgoat | False | 5105 | 4987 | 2716 | 2271 | 0.728 | 0.982 | 0 | 0 | 0 | 0 | 0.956 | 0.976 | 985 |

### Stage and defence

| site | stage requests | stage acc ML | stage acc rules | furthest ML | furthest rules | exploitation found ML/rules | defence action right ML | defence action right rules | defence attackers allowed ML | defence attackers allowed rules | defence normal users blocked ML | defence normal users blocked rules |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| juiceshop | 2748 | 0.999 | 0.925 | 0.987 | 0.921 | 1.00/0.00 (n=13) | 1.0 | 0.774 | 0.0 | 0.0 | 0.0 | 0.0 |
| dvwa | 2702 | 0.969 | 0.637 | 0.986 | 0.597 | 0.99/0.00 (n=255) | 1.0 | 0.671 | 0.0 | 0.0 | 0.0 | 0.0 |
| bwapp | 2675 | 0.985 | 0.736 | 0.975 | 0.72 | 0.97/0.00 (n=130) | 1.0 | 0.63 | 0.0 | 0.0 | 0.0 | 0.0 |
| mutillidae | 2612 | 0.958 | 0.93 | 0.908 | 0.705 | 0.72/0.00 (n=183) | 0.991 | 0.618 | 1.0 | 1.0 | 0.0 | 0.0 |
| dvna | 2563 | 0.975 | 0.929 | 0.986 | 0.569 | 0.90/0.00 (n=183) | 0.998 | 0.62 | 0.0 | 0.0 | 0.0 | 0.0 |
| vampi | 2703 | 1.0 | 0.982 | 1.0 | 0.864 | 1.00/0.00 (n=48) | 0.991 | 0.715 | 4.0 | 4.0 | 0.0 | 0.0 |
| dvga | 2692 | 0.99 | 0.895 | 0.996 | 0.844 | 0.97/0.84 (n=38) | 0.993 | 0.628 | 1.0 | 1.0 | 0.0 | 0.0 |
| webgoat | 1976 | 0.977 | 0.98 | 0.956 | 0.971 | 0.00/1.00 (n=7) | 0.939 | 0.559 | 27.0 | 27.0 | 0.0 | 0.0 |

### Next step (ceiling 0.38 from the generator's random choice)

| site | next campaigns | next top-1 (true order) | next top-3 (true order) | next top-1 (order read) | next top-3 (order read) |
|---|---|---|---|---|---|
| juiceshop | 60.0 | 0.279 | 0.849 | 0.0 | 0.667 |
| dvwa | 60.0 | 0.279 | 0.849 | 0.0 | 0.714 |
| bwapp | 60.0 | 0.279 | 0.849 |  |  |
| mutillidae | 60.0 | 0.279 | 0.849 | 1.0 | 1.0 |
| dvna | 60.0 | 0.279 | 0.849 |  |  |
| vampi | 60.0 | 0.279 | 0.849 | 0.0 | 1.0 |
| dvga | 60.0 | 0.279 | 0.849 | 0.0 | 0.75 |
| webgoat | 60.0 | 0.279 | 0.849 |  |  |

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
| dalfox | bwapp | True | 56 | 0.089 | 0.125 | 0 | 0 | allow,block | allow,rate_limit | 0 |
| dalfox | mutillidae | True | 64 | 0.609 | 0.844 | 0 | 29 | allow,block | allow,block | 0 |
| dalfox | dvna | True | 37 | 0.027 | 0.135 | 0 | 0 | allow | allow | 0 |
| dalfox | vampi | True | 34 | 0.029 | 0.147 | 0 | 0 | allow | allow | 0 |
| dalfox | dvga | True | 57 | 0.053 | 0.088 | 0 | 0 | allow,block | allow,rate_limit | 0 |
| medusa | bwapp | True | 200 | 1.0 | 1.0 | 0 | 0 | rate_limit | block | 0 |
| medusa | mutillidae | True | 200 | 1.0 | 1.0 | 0 | 29 | rate_limit | block | 0 |

Run time: 531 s.
