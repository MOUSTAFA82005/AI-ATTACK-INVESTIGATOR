# v11 SEALED TEST: Biblio-US17, 2017-06-01 .. 2017-07-17 (run once)

Preregistration: results/final_v11/PREREGISTRATION.md (+ Amendment 1). Payload layer only (no IP, user agent or body in this dataset). v10 never saw Biblio-US17 (UNSEEN-SITE row); v11 was trained on Jan-May of the same site (SAME-SITE row, secondary). Threshold 0.7 preregistered, 0.8 sensitivity row.

Unique LVL1 attacks 121052 (raw rows 278426), attack families 567; clean sample 1000000 rows (14303 unique paths); signature false positives 174 unique; LVL2/3 unique 2109.

| detector | recall (macro over families, headline) | recall (unique) | recall (raw-weighted) | FA clean (rows) | FA clean (unique paths) | FA on signature false positives | LVL2/3 recall |
|---|---|---|---|---|---|---|---|
| payload rules | 0.0771 | 0.0611 | 0.0271 | 0.00000 | 0.00028 | 0.0000 | 0.0000 |
| v10 @0.7 | 0.7437 | 0.9970 | 0.9956 | 0.00004 | 0.00126 | 0.2471 | 0.0853 |
| v10 @0.8 | 0.7345 | 0.9968 | 0.9955 | 0.00001 | 0.00084 | 0.1667 | 0.0853 |
| v11 @0.7 | 0.8199 | 0.9987 | 0.9976 | 0.00000 | 0.00007 | 0.0115 | 0.0759 |
| v11 @0.8 | 0.8126 | 0.9986 | 0.9975 | 0.00000 | 0.00007 | 0.0057 | 0.0759 |

## Pre-stated reading

v11 is better on Biblio if macro recall(v11) >= recall(v10) + 0.02 AND FA clean and FA on signature false positives are not higher than v10 (all at 0.7): 0.8199 vs 0.7437 + 0.02, FA clean 0.00000 vs 0.00004, FA false positives 0.0115 vs 0.2471 -> **BETTER**.

Known bias (preregistered): labels start from signature tools plus manual review, so recall is recall on signature-confirmed attacks and FA on clean is an upper bound. This test says nothing new about unseen sites for v11; site independence evidence stays the v10 sealed test.
