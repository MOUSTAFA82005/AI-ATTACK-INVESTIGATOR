# TALON INVESTIGATOR: the whole project on one page

AI2 course project, Faculty of Computers and Information, Mansoura University.
Final version: **v12** (git tag `v12.0-final-test`). Every number below comes from a file in `results/`.

---

## 1. What it is

You upload a web server access log. TALON reads every request and tells you:

- which requests are attacks, and what type (SQLi, XSS, traversal, command injection, SSTI, SSRF, XXE, ...);
- which visitors are attackers, what they tried and how far they got (recon, intrusion, exploitation, data theft);
- what they will probably try next;
- whether to block, rate-limit or allow them, and how to fix the weakness (OWASP / CWE).

It is built to work on **any** site's log, not only the sites it was trained on.

```
access log ─► parser ─► detector ─► sessions ─► attack type ─► stage ─► next step ─► defence
             (6 formats) (per request) (per visitor)                                (action + fix)
```

| Part | Model |
|---|---|
| Is this request an attack? | XGBoost on site-independent features of method, path, query and body (threshold 0.7) |
| What is this visitor doing? | XGBoost on per-visitor behaviour (normal, brute force, enumeration, scan) + known-probe list |
| Attack type | XGBoost |
| Attack stage | XGBoost |
| Next step | Markov chain |
| Block / rate-limit / allow | Decision tree (+ one rule: a critical visitor is always blocked) |
| How to fix | k-NN (TF-IDF) over a 24-entry OWASP / CWE knowledge base |
| Unusual requests | Isolation Forest (review mark only, never changes a verdict) |

The dashboard (FastAPI + plain HTML/JS) has accounts with e-mail login codes, saved investigations, notifications,
trusted addresses, and masks passwords and tokens in results. Everything runs on one machine, offline.

---

## 2. How we tested it: sealed tests

A sealed test is an exam kept in a closed envelope.

1. **Set the test data aside** before anyone looks at it.
2. **Seal it with a hash** (SHA-256 of every file, in `results/final_vN/hashes.txt`). Change one byte and the hash changes, so anyone can check the files were not touched.
3. **Write the pass rule first** (`results/final_vN/PREREGISTRATION.md`), so the measure cannot be changed after seeing the result.
4. **Freeze the code and models** (git tag + `model_hashes.txt`), **run once**, and report the result as it is. The data is then never used again.

Every result also has a **rules-only baseline** next to it (payload rules + rule-based sessions), so you can see what the models add.

---

## 3. Results of the final system

v12 keeps the v11 models and adds three code fixes; its regression run on every older test set gives the same numbers as before, so these rows describe the system the dashboard runs today. The one exception is the first library row: the v10 detector, before any training on that site.

### Attacks caught

| Test | Rules only | TALON |
|---|---|---|
| Lab, 7 vulnerable apps, attacks from our traffic generator (SQLi, XSS, traversal, command injection, brute force, scans and more) | 0.598 to 0.994 | **0.988 to 1.000** |
| REST API (VAmPI) | 0.598 | **0.988** |
| GraphQL API (DVGA) | 0.692 | **0.995** |
| University library (Biblio-US17), attack families, site never seen in training (v10 detector) | 0.077 | **0.744** |
| Same library, two later months, after training on its first five months (v11 detector) | 0.077 | **0.820** |

### False alarms on real traffic

| Test | Rules only | TALON |
|---|---|---|
| Lab normal users, 7 apps | up to 29 users | **0** |
| ClarkNet, 300,000 requests, site never seen in training | 1.66% | **0.46%** |
| NASA, 300,000 requests, new month | 0.06% | **0.01%** |
| Zanbil online shop, 400,000 requests, unused part | 0.11% | **0.01%** |
| University library, 1,000,000 normal requests | 0 | **0** |
| secrepo.com, 15 sealed days, 4,208 real visitors | 0.90% | **0.00%** (none blocked) |

### Investigation (lab, 7 apps)

| | Rules only | TALON |
|---|---|---|
| Attack stage right | 0.64 to 0.98 | **0.96 to 1.00** |
| Block / rate-limit / allow right | 0.70 to 0.80 | **0.99 to 1.00** |

### Versions in one line each

| Version | What changed | Sealed result |
|---|---|---|
| v8 | Full pipeline, 7 lab apps + real tools | Lab F1 0.970 to 0.996, 0 false alarms on normal users |
| v9 | New data sources, threshold | ModSec-WP SQLi 0.984, XSS 0.951; Indonesian logs false alarms 0.466 → 0.0004 |
| v10 | Visitor = IP + browser, retrained | Lower session false alarms than v9 on ClarkNet and USask |
| v11 | Detector also trained on Biblio-US17 Jan-May | Jun-Jul of the same site: 0.820 vs 0.744 (v10), false alarms 0 |
| v12 | 3 code fixes from real traffic, no retraining | secrepo 15 days: attackers caught 0.145 → 0.313, normal visitors blocked 19 → 0: **better** |

Full tables: `README.md` → Results, and `results/final_vN/`.

---

## 4. Future work

Address reputation (threat-intelligence feeds), more real behaviour data (enumeration, multi-step attacks), a live mode that reads the log as it is written, pushing the suggested rules straight to ModSecurity or Nginx, and learning each site's normal traffic.

---

## 5. Team

| Member | Role |
|---|---|
| Mostafa Safi Mostafa Soliman | Data (datasets, conversion, labels), models and training, frontend (dashboard and landing page) |
| Mostafa El-Hassanein El-Hassanein El-Shaarawy | Running the tests, Docker lab, traffic generator |
| Mariam Mohamed Mansour | Backend (FastAPI server and investigation API) |

Instructor: Dr. Sara El-Metwally · TA: Eng. Asmaa Nagib

---

## 6. Run it

Follow `README.md` → Quick start: clone, install `deploy/requirements.txt`, unpack
[`talon-models-v12.zip`](https://github.com/MOUSTAFA82005/AI-ATTACK-INVESTIGATOR/releases/download/v12.0-final-test/talon-models-v12.zip)
from the `v12.0-final-test` release, then:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --port 8000
```

Open http://127.0.0.1:8000, log in, **New investigation**, upload a log.

Tests: `python -m pytest -q` → 320 passed.
