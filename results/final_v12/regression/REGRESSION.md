# v12 regression (dev use, sets opened before)

Pass rule (PREREGISTRATION step 3): v12 not worse than v11 by more than 0.005 on any headline number.

## Real traffic (false alarms on rule-normal requests)

| log | v11 payload FA | v11 + sessions FA | v11 IPs flagged | v12 payload FA | v12 + sessions FA | v12 IPs flagged |
|---|---|---|---|---|---|---|
| S1 ClarkNet (unseen site, headline) | 0.00132 | 0.00462 | 138 | 0.00132 | 0.00462 | 138 |
| S2 USask (unseen site, headline) | 0.0006 | 0.00685 | 276 | 0.0006 | 0.00685 | 276 |
| S3 NASA Aug 1995 (same site as training, secondary) | 1e-05 | 0.00011 | 8 | 1e-05 | 0.00011 | 8 |
| S4 zanbil 5.0M + 8.0M (same site, secondary) | 8e-05 | 8e-05 | 26 | 8e-05 | 8e-05 | 26 |
| S5 secrepo, 6 new days (same site as dev, real scanners unlabelled) | 0.0027 | 0.10113 | 6 | 0.0 | 0.10019 | 9 |

## Biblio-US17 sealed rows (payload layer, 0.7)

| | macro | unique | raw | fa_clean | fa_clean_paths | fa_fp | lvl |
|---|---|---|---|---|---|---|---|
| v11 | 0.81990 | 0.99869 | 0.99760 | 0.00000 | 0.00007 | 0.01149 | 0.07587 |
| v12 | 0.81990 | 0.99869 | 0.99760 | 0.00000 | 0.00007 | 0.01149 | 0.07587 |
