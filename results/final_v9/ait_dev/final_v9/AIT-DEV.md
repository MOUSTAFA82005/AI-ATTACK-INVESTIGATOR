# AIT dev check: final_v9

Context model: `models/context.joblib`. Hosts onion,spiral (not used in training).
Recall rows = share caught; FA rows = number of normal requests flagged.

| host | what | requests | ML | rules |
|---|---|---|---|---|
| onion | bruteforce | 48 | 1.0 | 1.0 |
| onion | bruteforce page loads | 49 | 0.0 | 0.0 |
| onion | scan | 6295 | 1.0 | 0.589 |
| onion | upload | 5 | 0.4 | 0.2 |
| onion | webshell | 1 | 1.0 | 1.0 |
| onion | FA: normal user on the attacker's IP | 64935 | 43 | 1355 |
| onion | FA: all other normal users | 10628 | 0 | 22 |
| onion | stage accuracy (attack requests the pipeline flagged) | 6346 | 1.0 | 0.867 |
| onion | furthest stage per attacker session |  | 1.0 | 1.0 |
| onion | exploitation found ML/rules |  | 1.00/0.00 (n=3) |  |
| onion | stage recon: predicted as | 6295 | {'recon': 6295} |  |
| onion | stage intrusion: predicted as | 48 | {'intrusion': 48} |  |
| onion | stage exploitation: predicted as | 6 | {'none': 3, 'exploitation': 3} |  |
| spiral | bruteforce | 137 | 1.0 | 1.0 |
| spiral | bruteforce page loads | 183 | 0.0 | 0.0 |
| spiral | scan | 6296 | 0.998 | 0.59 |
| spiral | upload | 5 | 0.4 | 0.2 |
| spiral | webshell | 5 | 0.2 | 0.2 |
| spiral | FA: normal user on the attacker's IP | 82467 | 15 | 1018 |
| spiral | FA: all other normal users | 11352 | 0 | 37 |
| spiral | stage accuracy (attack requests the pipeline flagged) | 6425 | 1.0 | 0.855 |
| spiral | furthest stage per attacker session |  | 1.0 | 1.0 |
| spiral | exploitation found ML/rules |  | 0.67/0.00 (n=3) |  |
| spiral | stage recon: predicted as | 6296 | {'recon': 6285, 'none': 11} |  |
| spiral | stage intrusion: predicted as | 137 | {'intrusion': 137} |  |
| spiral | stage exploitation: predicted as | 10 | {'none': 7, 'exploitation': 2, 'intrusion': 1} |  |

## Normal requests flagged by ML, by behaviour

| behaviour | onion | spiral |
|---|---|---|
|  | 3 | 4 |
| bruteforce | 37 | 11 |
| scan | 3 | 0 |
