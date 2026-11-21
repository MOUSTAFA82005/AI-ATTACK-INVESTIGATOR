# Biblio-US17 dev check: v10, split train

Unique LVL1 attacks 1366 (raw rows 8191), clean sample 600000 rows (15098 unique paths), signature false positives 484 unique, LVL2/3 unique 666, attack families 432.

| detector | recall (macro over families, headline) | recall (unique) | recall (raw-weighted) | FA clean (rows) | FA clean (unique paths) | FA on signature false positives | LVL2/3 recall |
|---|---|---|---|---|---|---|---|
| payload rules | 0.2212 | 0.6069 | 0.7723 | 0.0000 | 0.0004 | 0.0124 | 0.0000 |
| v10 @0.7 | 0.2243 | 0.4092 | 0.1308 | 0.0000 | 0.0002 | 0.0992 | 0.0646 |
| v10 @0.8 | 0.2072 | 0.3902 | 0.1234 | 0.0000 | 0.0001 | 0.0661 | 0.0646 |
