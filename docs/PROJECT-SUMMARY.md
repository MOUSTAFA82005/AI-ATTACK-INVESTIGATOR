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
and masks passwords and tokens in results. Everything runs on one machine, offline.

---

## 2. How we tested it: sealed tests

A sealed test is an exam kept in a closed envelope.

1. **Set the test data aside** before anyone looks at it.
2. **Seal it with a hash** (SHA-256 of every file, in `results/final_vN/hashes.txt`). Change one byte and the hash changes, so anyone can check the files were not touched.
3. **Write the pass rule first** (`results/final_vN/PREREGISTRATION.md`), so the measure cannot be changed after seeing the result.
4. **Freeze the code and models** (git tag + `model_hashes.txt`), **run once**, and report the result as it is. The data is then "burned": never used again.

Every result also has a **rules-only baseline** next to it (payload rules + rule-based sessions), so you can see what the models add.

---

## 3. Results (all sealed, all run once)

### Attacks caught

| Test | Rules only | TALON |
|---|---|---|
| Lab, 7 vulnerable apps attacked with real tools (sqlmap, nikto, gobuster, feroxbuster, wfuzz, hydra, medusa, dalfox), attack F1 | 0.68 to 0.994 | **0.970 to 0.996** |
| Lab, REST API (VAmPI), recall | 0.598 | **0.988** |
| Lab, GraphQL API (DVGA), recall | 0.692 | **0.995** |
| University library log (Biblio-US17), site **never seen** in training (v10), attack families caught | 0.077 | **0.744** |

### False alarms on real traffic

| Test | Rules only | TALON |
|---|---|---|
| Lab normal users, 7 apps | | **0** |
| ClarkNet, 300,000 requests, site never seen (v10, % of requests) | 1.66% | **0.46%** |
| NASA, 300,000 requests, new month (v10) | 0.06% | **0.01%** |
| Zanbil online shop, 400,000 requests, unused part (v10) | 0.11% | **0.01%** |
| Public website (secrepo.com), 15 days, 4,208 real visitors (v12, % of visitors) | 0.90% (38) | **0.00% (0)** |

### Real internet traffic, 15 days (v12): zero false alarms

v12 raised **zero** false alarms on 4,208 real visitors (rules: 38) and caught the same 26 of 83 attacker visitors as the rules; of attackers with 10 or more requests it caught 70%.
The overall catch depends on how much an attacker did; almost half sent one single request all day (post-hoc breakdown, analysis only):

| Requests sent by the attacker | Attackers | v12 caught | Rules caught |
|---|---|---|---|
| 1 | 38 | 2 | 1 |
| 2 | 5 | 0 | 0 |
| 3-4 | 6 | 3 | 3 |
| 5-9 | 7 | 2 | 2 |
| 10 or more | 27 | **19 (70%)** | 20 |
| all | 83 | **26 (31%)** | 26 (31%) |

- Of the 57 missed, **only 1 sent an attack payload**. Most asked once for a random script name (`/fdgq.php`), a CMS
  endpoint or a secret file. From one log line that is the same as a visitor following a broken link.
- secrepo.com is a static folder of files: no forms, no database, no login. Its attackers are blind scanners, the hardest case for any detector.
- All 12 WordPress-install finders were caught (v11: 0).

**One sentence for the discussion:** "On 15 days of real internet traffic we caught 70% of attackers who sent 10 or
more requests, with zero false alarms on 4,208 visitors. Of the attackers we missed, 38 sent a single request
with no payload, which cannot be told apart from a visitor following a broken link, and rules missed them too."

### Versions in one line each

| Version | What changed | Sealed result |
|---|---|---|
| v8 | Full pipeline, 7 lab apps + real tools | Lab F1 0.970-0.996, 0 false alarms on normal users |
| v9 | New data sources, threshold | ModSec-WP SQLi 0.984, XSS 0.951; Indonesian logs false alarms 0.466 → 0.0004 |
| v10 | Visitor = IP + browser, retrained | Lower session false alarms than v9 on ClarkNet and USask |
| v11 | Detector also trained on Biblio-US17 Jan-May | Same-site Jun-Jul: 0.820 vs 0.744 (v10), false alarms 0 |
| v12 | 3 code fixes from real traffic, no retraining | secrepo 15 days: caught 0.145 → 0.313, normal blocked 19 → 0: **BETTER** |

v12 is the last version: its preregistration says "No v13".

---

## 4. Team

| Member | Role |
|---|---|
| Mostafa Safi Mostafa Soliman | Data (datasets, conversion, labels), models and training, frontend (dashboard and landing page) |
| Mostafa El-Hassanein El-Hassanein El-Shaarawy | Running the tests, Docker lab, traffic generator |
| Mariam Mohamed Mansour | Backend (FastAPI server and investigation API) |

Instructor: Dr. Sara El-Metwally · TA: Eng. Asmaa Nagib

---

## 5. Run it

Follow the [Quick start](../README.md#quick-start-windows) in the README: clone, install, download the models from the `v12.0-final-test` release, then start the server:

```powershell
python -m uvicorn backend.app.main:app --port 8000
```

Open http://127.0.0.1:8000, log in, choose **New investigation** and upload an access log.

Tests: `python -m pytest -q`.
