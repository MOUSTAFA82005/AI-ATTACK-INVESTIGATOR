# v11 sealed test: post-hoc analysis (analysis only, no model or number changed)

567 attack families, 121052 unique LVL1 attacks. A family counts as missed when its recall is below 0.5 (most of its URIs pass). Shape = what the request looks like (dominant class in the family), first match in this order: dot-segment / file access, SQL keywords, script / HTML, command, encoded (percent escapes), known-file probe (extension), odd method, query without keywords, plain path.

## 1. Family recall by request shape (macro over the families of that shape)

| shape | families | rules | v10 | v11 |
|---|---|---|---|---|
| encoded (percent escapes) | 312 | 0.031 | 0.872 | 0.947 |
| plain path | 163 | 0.000 | 0.831 | 0.831 |
| known-file probe (extension) | 52 | 0.019 | 0.019 | 0.019 |
| dot-segment / file access | 28 | 1.000 | 0.331 | 1.000 |
| script / HTML | 5 | 0.400 | 0.600 | 0.600 |
| query without keywords | 4 | 0.000 | 0.000 | 0.250 |
| SQL keywords | 3 | 0.977 | 0.314 | 0.319 |

## 2. Missed families (recall < 0.5) by family size

| size | families | missed rules | missed v10 | missed v11 |
|---|---|---|---|---|
| 1 URI | 387 | 364 | 98 | 89 |
| 2 | 55 | 47 | 6 | 1 |
| 3-5 | 81 | 76 | 9 | 9 |
| 6-20 | 9 | 4 | 6 | 2 |
| >20 | 35 | 31 | 2 | 0 |

## 3. Who catches what (families, recall >= 0.5 = caught)

| group | families | of which shape (top 3) |
|---|---|---|
| v11 caught, v10 missed | 20 | dot-segment / file access 19, query without keywords 1 |
| v10 caught, v11 missed | 0 |  |
| rules caught, v11 missed | 2 | SQL keywords 2 |
| v11 caught, rules missed | 423 | encoded (percent escapes) 285, plain path 136, script / HTML 1 |
| all three missed | 99 | known-file probe (extension) 51, plain path 27, encoded (percent escapes) 16 |

## 4. LVL2/3 recall by level (secondary set, never trained on)

| level | unique | rules | v10 | v11 |
|---|---|---|---|---|
| 2 | 1641 | 0.000 | 0.005 | 0.005 |
| 3 | 468 | 0.000 | 0.368 | 0.325 |

LVL2/3 shapes (top 5): known-file probe (extension) 1051, encoded (percent escapes) 842, plain path 213, query without keywords 3
