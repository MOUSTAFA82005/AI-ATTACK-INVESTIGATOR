# Defence replay on AIT: v9

Hosts not used in training. See the module docstring for the method.

## Summary

| host | who | blocked at | attack requests after block | bruteforce stopped | upload stopped | webshell stopped | action on attacker at end | other users' sessions blocked | other users' sessions rate-limited | other users' sessions |
|---|---|---|---|---|---|---|---|---|---|---|
| onion | ML | 2020-03-04 18:46:13+00:00 | 0.971 | True | True | True | block | 0 | 0 | 23 |
| onion | rules | 2020-03-04 18:46:13+00:00 | 0.971 | True | True | True | block | 0 | 0 | 23 |
| spiral | ML | 2020-03-04 18:02:05+00:00 | 0.953 | True | True | True | block | 1 | 0 | 47 |
| spiral | rules | 2020-03-04 18:02:05+00:00 | 0.953 | True | True | True | block | 0 | 1 | 47 |

## Action on the attacker at each checkpoint

| host | checkpoint | time | ML | rules |
|---|---|---|---|---|
| onion | after attack request 1 | 2020-03-04 18:46:13+00:00 | block | block |
| onion | after attack request 3 | 2020-03-04 18:46:13+00:00 | block | block |
| onion | after attack request 10 | 2020-03-04 18:46:13+00:00 | block | block |
| onion | after attack request 30 | 2020-03-04 18:46:13+00:00 | block | block |
| onion | after attack request 100 | 2020-03-04 18:46:13+00:00 | block | block |
| onion | after attack request 300 | 2020-03-04 18:46:14+00:00 | block | block |
| onion | after attack request 1000 | 2020-03-04 18:46:16+00:00 | block | block |
| onion | after attack request 3000 | 2020-03-04 18:46:22+00:00 | block | block |
| onion | after first bruteforce | 2020-03-04 18:50:51+00:00 | block | block |
| onion | after first upload | 2020-03-04 18:55:04+00:00 | block | block |
| spiral | after attack request 1 | 2020-03-04 18:01:23+00:00 | allow | allow |
| spiral | after attack request 3 | 2020-03-04 18:01:23+00:00 | allow | allow |
| spiral | after attack request 10 | 2020-03-04 18:01:24+00:00 | allow | allow |
| spiral | after attack request 30 | 2020-03-04 18:01:27+00:00 | rate_limit | rate_limit |
| spiral | after attack request 100 | 2020-03-04 18:01:36+00:00 | rate_limit | rate_limit |
| spiral | after attack request 300 | 2020-03-04 18:02:05+00:00 | block | block |
| spiral | after attack request 1000 | 2020-03-04 18:03:48+00:00 | block | block |
| spiral | after attack request 3000 | 2020-03-04 18:08:47+00:00 | block | block |
| spiral | after first bruteforce | 2020-03-04 18:23:44+00:00 | block | block |
| spiral | after first upload | 2020-03-04 18:28:05+00:00 | block | block |
