# v12 sealed test: secrepo.com, 15 unseen days of November 2026 (run once)

Preregistration: results/final_v12/PREREGISTRATION.md (+ Amendment 1). Labels per (day, IP) from the raw lines by eval/v12_label.py, written and hashed before any system ran (results/final_v12/labels_sha256.txt).
Unsure visitors left out: 19938 (Chrome/146 scraper fleet, declared crawlers on exploit-looking paths, one admin guess).

| system | attacker visitors | caught | normal visitors | normal with alarm | normal blocked | attackers blocked or rate-limited |
|---|---|---|---|---|---|---|
| rules + rule sessions | 83 | 0.313 (26) | 4208 | 0.0090 (38) |  |  |
| v11 (app) | 83 | 0.145 (12) | 4208 | 0.0045 (19) | 19.0 | 0.133 |
| v12 (app) | 83 | 0.313 (26) | 4208 | 0.0000 (0) | 0.0 | 0.301 |

## Pre-stated reading

v12 better if caught >= v11 + 0.05 (0.313 vs 0.145), normal blocked <= v11 (0 vs 19), normal alarm <= v11 + 0.01 (0.0000 vs 0.0045) -> **BETTER**.

## Post-hoc look at the misses (analysis only, nothing changed after the run)
- v12 missed 57 of 83 attacker visitors: 31 asked for one random server-script name (/fdgq.php, /1234.php ...,
  no list can know them), 8 CMS endpoints not on the list, 4 secret files, 3 admin/login guesses, 3 WordPress probes.
  All 12 HEAD install finders were caught (v11: 0).
- Unsure visitors (not counted): no system alarmed any of the 19,795 Chrome/146 fleet IPs; declared crawlers on
  exploit-looking paths: v11 alarmed 1 of 142, v12 16 of 142 (none blocked).
- Run: laptop, code = 1ddddea content (git HEAD c58e161 + identical uncommitted files), v11 = worktree c58e161,
  same models (results/final_v12/model_hashes.txt).
