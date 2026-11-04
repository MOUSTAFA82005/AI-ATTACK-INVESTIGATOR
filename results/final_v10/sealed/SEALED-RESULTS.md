# v10 sealed test

Run once at tag v10.0-final-test. Rules, frozen v9 and v10 on the same converted rows.
FA = share of normal requests flagged (normal = not called an attack by the payload rules).

## False alarms on real traffic

| log | requests | rule-flagged (not counted) | distinct hosts/IPs | rules + rule sessions | v9 payload | v9 + sessions | v10 payload | v10 + sessions |
|---|---|---|---|---|---|---|---|---|
| S1 ClarkNet (unseen site, headline) | 300000 | 25 | 20231 | 0.0166 | 0.0016 | 0.0049 | 0.0013 | 0.0046 |
| S2 USask (unseen site, headline) | 300000 | 428 | 27768 | 0.0015 | 0.0006 | 0.0069 | 0.0006 | 0.0068 |
| S3 NASA Aug 1995 (same site as training, secondary) | 300000 | 2 | 18322 | 0.0006 | 0.0 | 0.0001 | 0.0 | 0.0001 |
| S4 zanbil 5.0M + 8.0M (same site, secondary) | 400000 | 47 | 12599 | 0.0011 | 0.0001 | 0.0001 | 0.0001 | 0.0001 |
| S5 secrepo, 6 new days (same site as dev, real scanners unlabelled) | 7417 | 1 | 1095 | 0.1069 | 0.0027 | 0.1011 | 0.0027 | 0.1011 |

## Pre-stated reading

v10 session FA lower than v9 on both S1 and S2: **yes** (S1 True, S2 True). S6 (lab) is reported separately if it was run.
