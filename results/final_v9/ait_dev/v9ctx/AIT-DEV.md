# AIT dev check: v9ctx

Context model: `models\context_v9.joblib`. Hosts onion,spiral (not used in training).
Recall rows = share caught; FA rows = number of normal requests flagged.

| host | what | requests | ML | rules |
|---|---|---|---|---|
| onion | bruteforce | 48 | 1.0 | 1.0 |
| onion | bruteforce page loads | 49 | 0.0 | 0.0 |
| onion | scan | 6295 | 1.0 | 0.589 |
| onion | upload | 5 | 0.4 | 0.2 |
| onion | webshell | 1 | 1.0 | 1.0 |
| onion | FA: normal user on the attacker's IP | 64935 | 65.0 | 1355.0 |
| onion | FA: all other normal users | 10628 | 2.0 | 22.0 |
| spiral | bruteforce | 137 | 1.0 | 1.0 |
| spiral | bruteforce page loads | 183 | 0.0 | 0.0 |
| spiral | scan | 6296 | 0.999 | 0.59 |
| spiral | upload | 5 | 0.4 | 0.2 |
| spiral | webshell | 5 | 0.2 | 0.2 |
| spiral | FA: normal user on the attacker's IP | 82467 | 33.0 | 1018.0 |
| spiral | FA: all other normal users | 11352 | 2.0 | 37.0 |

## Normal requests flagged by ML, by behaviour

| behaviour | onion | spiral |
|---|---|---|
|  | 27 | 24 |
| bruteforce | 37 | 11 |
| scan | 3 | 0 |
