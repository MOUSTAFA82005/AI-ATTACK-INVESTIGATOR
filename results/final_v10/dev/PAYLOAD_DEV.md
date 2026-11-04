# v10 dev: payload detector, share flagged at threshold 0.7

| set | rows | detector flagged | detector_v10 flagged |
|---|---|---|---|
| ModSec-WP half 1: normal | 4902 | 0.1603 | 0.0131 |
| ModSec-WP half 1: normal login POSTs | 56 | 1.0 | 0.0 |
| ModSec-WP half 1: sqli | 34641 | 0.9863 | 0.9864 |
| ModSec-WP half 1: xss | 3972 | 0.9741 | 0.9753 |
| ModSec-WP half 1: fileinclusion | 3244 | 0.9531 | 0.9716 |
| ModSec-WP half 1: rce | 2235 | 0.6456 | 0.7409 |
| ModSec-WP half 1: bruteforce | 3884 | 1.0 | 0.0 |
| Indonesian (300k sample): normal | 299779 | 0.0004 | 0.0005 |
| Indonesian (300k sample): rule attacks | 221 | 0.1176 | 0.1176 |
| SR-BH sealed days: normal | 311759 | 0.0 | 0.0 |
| zanbil 10.0M: all | 200000 | 0.0001 | 0.0001 |
| Glastopf sealed: requests | 2865 | 0.0419 | 0.0419 |