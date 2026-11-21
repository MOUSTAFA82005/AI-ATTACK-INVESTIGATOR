# Biblio-US17 dev check: v10_cloud, split holdout

Unique LVL1 attacks 17166 (raw rows 41289), clean sample 155000 rows (6031 unique paths), signature false positives 145 unique, LVL2/3 unique 590, attack families 250.

| detector | recall (macro over families, headline) | recall (unique) | recall (raw-weighted) | FA clean (rows) | FA clean (unique paths) | FA on signature false positives | LVL2/3 recall |
|---|---|---|---|---|---|---|---|
| payload rules | 0.2100 | 0.0175 | 0.0379 | 0.0000 | 0.0000 | 0.0138 | 0.0000 |
| v10_cloud @0.7 | 0.3340 | 0.9723 | 0.9530 | 0.0000 | 0.0002 | 0.2276 | 0.0441 |
| v10_cloud @0.8 | 0.3219 | 0.9719 | 0.9524 | 0.0000 | 0.0002 | 0.1586 | 0.0424 |
