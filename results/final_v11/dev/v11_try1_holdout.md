# Biblio-US17 dev check: v11_try1, split holdout

Unique LVL1 attacks 17166 (raw rows 41289), clean sample 155000 rows (6031 unique paths), signature false positives 145 unique, LVL2/3 unique 590, attack families 250.

| detector | recall (macro over families, headline) | recall (unique) | recall (raw-weighted) | FA clean (rows) | FA clean (unique paths) | FA on signature false positives | LVL2/3 recall |
|---|---|---|---|---|---|---|---|
| payload rules | 0.2100 | 0.0175 | 0.0379 | 0.0000 | 0.0000 | 0.0138 | 0.0000 |
| v11_try1 @0.7 | 0.5604 | 0.9915 | 0.9906 | 0.0000 | 0.0002 | 0.1172 | 0.0458 |
| v11_try1 @0.8 | 0.5546 | 0.9909 | 0.9903 | 0.0000 | 0.0002 | 0.0759 | 0.0424 |
