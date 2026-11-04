# v9 sealed test: post-hoc analysis (no changes made)

## Why the session layer flags normal traffic on the Indonesian sites

| part | requests | normal | distinct IPs | share of requests from top IP | share of normal requests in the largest session | v9 sessions FA | rules sessions FA |
|---|---|---|---|---|---|---|---|
| 1 (organization-x) | 200000 | 199455 | 2 | 1.0 | 1.0 | 0.089 | 0.709 |
| 2 (organization-y) | 62656 | 62654 | 3 | 0.631 | 0.614 | 0.531 | 0.999 |
| 3 (organization-y) | 21926 | 21920 | 1635 | 0.183 | 0.183 | 0.216 | 0.215 |
| 4 (organization-y) | 200000 | 199989 | 7 | 0.999 | 0.999 | 0.844 | 0.912 |
| 5 (organization-y) | 199999 | 199995 | 6 | 0.919 | 0.891 | 0.724 | 0.777 |
| 6 (organization-y) | 200000 | 199905 | 14 | 0.876 | 0.874 | 0.369 | 0.288 |
| 7 (organization-y) | 155859 | 155588 | 3 | 0.809 | 0.804 | 0.365 | 0.395 |
| 8 (organization-y) | 200000 | 199988 | 4 | 0.982 | 0.976 | 0.97 | 0.85 |
| 9 (organization-y) | 153532 | 153335 | 9 | 0.75 | 0.747 | 0.383 | 0.406 |
| 10 (organization-y) | 120063 | 119855 | 6 | 0.791 | 0.788 | 0.425 | 0.439 |
| 11 (organization-y) | 183295 | 183286 | 16 | 0.892 | 0.888 | 0.628 | 0.745 |
| 12 (organization-y) | 173939 | 173781 | 3 | 0.832 | 0.83 | 0.585 | 0.367 |
| 13 (organization-y) | 199999 | 199984 | 3 | 0.974 | 0.962 | 0.798 | 0.829 |
| 14 (organization-y) | 199999 | 199987 | 3 | 0.979 | 0.975 | 0.972 | 0.582 |
| 15 (organization-y) | 86703 | 86699 | 3 | 0.621 | 0.617 | 0.189 | 0.246 |
| 16 (organization-y) | 127998 | 127783 | 3 | 0.846 | 0.841 | 0.355 | 0.294 |
| 17 (organization-y) | 105925 | 105785 | 864 | 0.111 | 0.077 | 0.367 | 0.63 |
| 18 (organization-y) | 66218 | 66218 | 3 | 0.606 | 0.602 | 0.168 | 0.223 |
| 19 (organization-y) | 200000 | 199862 | 3 | 0.921 | 0.917 | 0.542 | 0.527 |
| 20 (organization-y) | 199999 | 199880 | 3 | 0.97 | 0.948 | 0.921 | 0.831 |

## Same for ModSec-WP

| part | requests | normal | distinct IPs | share of requests from top IP | share of normal requests in the largest session | v9 sessions FA | rules sessions FA |
|---|---|---|---|---|---|---|---|
| 1 (all) | 108883 | 12597 | 7 | 0.781 | 0.131 | 0.585 | 0.215 |

## Brute force caught by the payload model in ModSec-WP: login shortcut?

| ModSec-WP rows | requests | v9 payload flags | with a body |
|---|---|---|---|
| normal login POSTs | 81 | 0.988 | 1.0 |
| bruteforce login POSTs | 488 | 1.0 | 1.0 |
| bruteforce, not a login POST | 7080 | 1.0 | 1.0 |
