# run7 final results

Frozen v8 models, run once, measured as fixed in `PREREGISTRATION.md`. ML = learned pipeline (`model + sessions`), rules = baseline (`rules + rule sessions`). Every number is reported whatever it shows.

## 1. Lab sites (WebGoat = unseen site)

| site | seen in training | log_lines | matched | attacks | normal requests | recall ML | recall rules | FA normal users ML | FA normal users rules | FA in attacker sessions ML | FA in attacker sessions rules | type acc ML | type acc rules | typed requests |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| juiceshop | True | 6321 | 6321 | 2749 | 3572 | 0.984 | 0.983 | 0 | 0 | 19 | 27 | 0.941 | 0.962 | 995 |
| dvwa | True | 5566 | 5553 | 2715 | 2838 | 0.988 | 0.975 | 0 | 0 | 26 | 14 | 0.944 | 0.955 | 999 |
| bwapp | True | 4650 | 4647 | 2697 | 1950 | 0.97 | 0.974 | 0 | 0 | 0 | 24 | 0.948 | 0.976 | 1013 |
| mutillidae | True | 4442 | 4362 | 2622 | 1740 | 0.996 | 0.994 | 0 | 29 | 2 | 133 | 0.957 | 0.96 | 994 |
| dvna | True | 4734 | 4602 | 2597 | 2005 | 0.991 | 0.973 | 0 | 0 | 22 | 22 | 0.972 | 0.971 | 1016 |
| vampi | True | 4625 | 4625 | 2734 | 1891 | 0.989 | 0.68 | 0 | 0 | 36 | 34 | 0.657 | 0.589 | 1004 |
| dvga | True | 4674 | 4626 | 2708 | 1918 | 0.971 | 0.693 | 0 | 0 | 5 | 27 | 0.946 | 0.951 | 1021 |
| webgoat | False | 5105 | 4987 | 2716 | 2271 | 0.693 | 0.984 | 0 | 0 | 24 | 24 | 0.962 | 0.975 | 992 |

### Stage and defence

| site | stage requests | stage acc ML | stage acc rules | furthest ML | furthest rules | exploitation found ML/rules | defence action right ML | defence action right rules | defence attackers allowed ML | defence attackers allowed rules | defence normal users blocked ML | defence normal users blocked rules |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| juiceshop | 2704 | 0.999 | 0.916 | 0.978 | 0.856 | 0.92/0.00 (n=13) | 0.993 | 0.963 | 0.0 | 0.0 | 0.0 | 0.0 |
| dvwa | 2683 | 0.969 | 0.634 | 0.956 | 0.411 | 1.00/0.00 (n=255) | 0.993 | 0.91 | 0.0 | 0.0 | 0.0 | 0.0 |
| bwapp | 2615 | 0.985 | 0.73 | 0.989 | 0.611 | 0.96/0.00 (n=130) | 0.993 | 0.9 | 0.0 | 0.0 | 0.0 | 0.0 |
| mutillidae | 2611 | 0.964 | 0.93 | 0.878 | 0.456 | 0.78/0.00 (n=183) | 0.993 | 0.893 | 0.0 | 0.0 | 0.0 | 0.0 |
| dvna | 2574 | 0.976 | 0.926 | 0.978 | 0.344 | 0.89/0.00 (n=190) | 0.993 | 0.893 | 0.0 | 0.0 | 0.0 | 0.0 |
| vampi | 2703 | 1.0 | 0.98 | 0.989 | 0.744 | 1.00/0.00 (n=48) | 0.997 | 0.923 | 0.0 | 0.0 | 0.0 | 0.0 |
| dvga | 2630 | 0.989 | 0.892 | 1.0 | 0.856 | 0.97/0.84 (n=38) | 0.993 | 0.9 | 0.0 | 0.0 | 0.0 | 0.0 |
| webgoat | 1881 | 0.985 | 0.993 | 0.83 | 0.943 | 0.00/1.00 (n=7) | 0.993 | 0.863 | 2.0 | 2.0 | 0.0 | 0.0 |

### Next step (ceiling 0.38 from the generator's random choice)

| site | next campaigns | next top-1 (true order) | next top-3 (true order) | next top-1 (order read) | next top-3 (order read) |
|---|---|---|---|---|---|
| juiceshop | 60.0 | 0.279 | 0.849 | 0.272 | 0.844 |
| dvwa | 60.0 | 0.279 | 0.849 | 0.282 | 0.84 |
| bwapp | 60.0 | 0.279 | 0.849 | 0.287 | 0.845 |
| mutillidae | 60.0 | 0.279 | 0.849 | 0.216 | 0.766 |
| dvna | 60.0 | 0.279 | 0.849 | 0.208 | 0.769 |
| vampi | 60.0 | 0.279 | 0.849 | 0.299 | 0.678 |
| dvga | 60.0 | 0.279 | 0.849 | 0.291 | 0.846 |
| webgoat | 60.0 | 0.279 | 0.849 | 0.25 | 0.854 |

## 2. Sealed tools

medusa ran on bWAPP and Mutillidae only (Amendment 2).

| tool | site | seen site | tool requests | caught ML | caught rules | normal users flagged ML | normal users flagged rules | tool action ML | tool action rules | normal users blocked ML |
|---|---|---|---|---|---|---|---|---|---|---|
| gobuster | juiceshop | True | 2 | 0.5 | 0.0 | 0 | 0 | rate_limit | rate_limit | 0 |
| gobuster | dvwa | True | 4615 | 1.0 | 1.0 | 0 | 0 | block | block | 0 |
| gobuster | bwapp | True | 4615 | 1.0 | 1.0 | 0 | 0 | block | block | 0 |
| gobuster | mutillidae | True | 4615 | 1.0 | 1.0 | 0 | 29 | block | block | 0 |
| gobuster | dvna | True | 4615 | 1.0 | 0.999 | 0 | 0 | block | block | 0 |
| gobuster | vampi | True | 4615 | 1.0 | 1.0 | 0 | 0 | block | block | 0 |
| gobuster | dvga | True | 4615 | 1.0 | 0.999 | 0 | 0 | block | block | 0 |
| feroxbuster | juiceshop | True | 37002 | 1.0 | 1.0 | 0 | 0 | block | block | 0 |
| feroxbuster | dvwa | True | 4639 | 1.0 | 1.0 | 0 | 0 | block | block | 0 |
| feroxbuster | bwapp | True | 23205 | 1.0 | 1.0 | 0 | 0 | block | block | 0 |
| feroxbuster | mutillidae | True | 28512 | 1.0 | 1.0 | 0 | 29 | block | block | 0 |
| feroxbuster | dvna | True | 23131 | 1.0 | 1.0 | 0 | 0 | block | block | 0 |
| feroxbuster | vampi | True | 9253 | 1.0 | 1.0 | 0 | 0 | block | block | 0 |
| feroxbuster | dvga | True | 4654 | 1.0 | 0.998 | 0 | 0 | block | block | 0 |
| wfuzz | juiceshop | True | 4616 | 1.0 | 1.0 | 0 | 0 | block | block | 0 |
| wfuzz | dvwa | True | 4614 | 1.0 | 1.0 | 0 | 0 | block | block | 0 |
| wfuzz | bwapp | True | 4614 | 1.0 | 1.0 | 0 | 0 | block | block | 0 |
| wfuzz | mutillidae | True | 4614 | 1.0 | 1.0 | 0 | 29 | block | block | 0 |
| wfuzz | dvna | True | 4614 | 1.0 | 0.999 | 0 | 0 | block | block | 0 |
| wfuzz | vampi | True | 4614 | 1.0 | 1.0 | 0 | 0 | block | block | 0 |
| wfuzz | dvga | True | 4614 | 1.0 | 0.999 | 0 | 0 | block | block | 0 |
| dalfox | juiceshop | True | 2 | 0.0 | 0.0 | 0 | 0 | allow | allow | 0 |
| dalfox | dvwa | True | 41 | 0.024 | 0.122 | 0 | 0 | allow | allow | 0 |
| dalfox | bwapp | True | 56 | 0.089 | 0.125 | 0 | 0 | block | block | 0 |
| dalfox | mutillidae | True | 64 | 0.078 | 0.891 | 0 | 29 | block | block | 0 |
| dalfox | dvna | True | 37 | 0.027 | 0.135 | 0 | 0 | allow | allow | 0 |
| dalfox | vampi | True | 34 | 0.029 | 0.147 | 0 | 0 | allow | allow | 0 |
| dalfox | dvga | True | 57 | 0.07 | 0.088 | 0 | 0 | block | rate_limit | 0 |
| medusa | bwapp | True | 200 | 1.0 | 1.0 | 0 | 0 | rate_limit | block | 0 |
| medusa | mutillidae | True | 200 | 1.0 | 1.0 | 0 | 29 | rate_limit | block | 0 |

## 3. Real logs: share of requests flagged

| log | requests | skipped lines | flagged ML | flagged rules | flagged ML n | flagged rules n | sessions | sessions flagged ML | sessions flagged rules | hand-label sample |
|---|---|---|---|---|---|---|---|---|---|---|
| zanbil_9.0-9.2M | 200000 | 0 | 0.0003 | 0.0036 | 65 | 726 | 4927 | 20 | 22 | 65 |
| secrepo_2024-10-03 | 25483 | 0 | 0.0023 | 0.0026 | 58 | 67 | 305 | 9 | 4 | 58 |
| secrepo_2024-10-10 | 39549 | 0 | 0.0009 | 0.0094 | 35 | 370 | 368 | 11 | 11 | 35 |
| secrepo_2024-10-15 | 37454 | 0 | 0.0006 | 0.0023 | 22 | 85 | 320 | 7 | 6 | 22 |
| secrepo_2025-04-22 | 10217 | 0 | 0.0702 | 0.0785 | 717 | 802 | 1181 | 16 | 21 | 200 |
| secrepo_2026-06-01 | 19251 | 0 | 0.0253 | 0.0158 | 487 | 305 | 563 | 19 | 4 | 200 |

## 4. Hand-labelled precision

Blind samples (up to 200 ML-flagged requests per log, seed 7007) are in `data/sealed/run7_hand_label/ (moved there after the run: the first path was not git-ignored)` (not committed: real log lines). Labelled with the criteria of PREREGISTRATION section 4; precision with a 95% interval comes from `python -m eval.run7_precision` after labelling.

Run time: 1017 s.
