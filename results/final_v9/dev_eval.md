# v9 dev check (payload detector, per request)

DEV data only, held out from training.

## SR-BH held-out DEV days 2020-07-19..2020-07-24 (per request)

| detector | attacks | recall vs CRS | normals | false alarms |
|---|---|---|---|---|
| detector | 34150 | 0.63 | 43007 | 0.0462 |
| detector_v9_holdout2 | 34150 | 0.665 | 43007 | 0.0142 |
| payload rules | 34150 | 0.352 | 43007 | 0.0002 |

| fam | requests | detector | detector_v9_holdout2 | payload rules |
|---|---|---|---|---|
| sqli | 21076 | 0.835 | 0.908 | 0.563 |
| protocol | 8727 | 0.086 | 0.055 | 0.007 |
| code_injection | 1860 | 0.974 | 0.969 | 0.05 |
| traversal | 1252 | 1.0 | 0.982 | 0.0 |
| spoofing | 1064 | 0.081 | 0.026 | 0.004 |
| cmdi | 173 | 0.994 | 1.0 | 0.116 |
| bruteforce | 148 | 0.142 | 0.142 | 0.007 |
| input_manipulation | 52 | 0.077 | 0.077 | 0.077 |
| scan | 1 | 0.0 | 0.0 | 0.0 |

## Glastopf held-out DEV months from 2015-01-01 (payload detector alone, no sessions)

| detector | requests | requests flagged | IPs | IPs flagged |
|---|---|---|---|---|
| detector | 2128 | 0.265 | 378 | 0.193 |
| detector_v9_holdout2 | 2128 | 0.265 | 378 | 0.193 |
| payload rules | 2128 | 0.045 | 378 | 0.098 |

## zanbil DEV lines 3,000,001-3,200,000 (real shop, normal traffic)

| detector | requests | flagged (false alarms) |
|---|---|---|
| detector | 200000 | 0.0002 |
| detector_v9_holdout2 | 200000 | 0.00025 |
| payload rules | 200000 | 0.00016 |
