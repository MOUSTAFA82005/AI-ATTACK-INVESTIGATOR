# TALON INVESTIGATOR

**AI Attack Investigator**. This is the AI2 course project of the Faculty of Computers and Information, Mansoura University.

You upload a web server access log. TALON then:

- finds the attack requests;
- groups the requests by visitor;
- tells you what each attacker tried and how far they got;
- guesses their next step;
- recommends whether to block, rate-limit or allow them;
- tells you how to fix the weakness they went for.

It is built to work on **any** access log, not just the sites it was trained on. That generalization is tested on sites the models have never seen.

> **Ethics.** Attack traffic was only ever sent to our own lab: vulnerable apps in Docker, reachable on 127.0.0.1 only. Never point any script in this repository at a real or third-party site. Lab traffic uses fake accounts and cards only, and raw logs are never committed.

---

## Contents

1. [What it does](#what-it-does)
2. [Quick start (Windows)](#quick-start-windows)
3. [The dashboard and accounts](#the-dashboard-and-accounts)
4. [Results](#results)
5. [Limitations](#limitations)
6. [Reproducibility](#reproducibility)
7. [Repository layout](#repository-layout)
8. [Tests](#tests)
9. [Team](#team)

---

## What it does

```
access log ──► parser ──► detector ──► sessions ──► attack type ──► stage ──► next step ──► defence
              (6 formats)  (per request)  (per visitor)                                  (action + fix)
```

| Step | Model | Code |
|---|---|---|
| Read the log | Detects the format by itself: combined, vhost, common, W3C/IIS, AWS ALB, JSON lines. UTF-8 or UTF-16. | `backend/app/log_parser.py` |
| Is this request an attack? | XGBoost (binary) on hand-made, site-independent features of method, path, query and body. Threshold 0.7 ("sensitive", preregistered) or 0.8 ("quiet"). | `ml/detector.py`, `ml/features.py` |
| What is this visitor doing? | XGBoost (normal, brute force, enumeration, scan) on per-visitor behaviour. A visitor is an IP plus a browser with the digits removed, with gaps under 30 minutes. | `ml/context_model.py`, `ml/sessions.py` |
| Attack type | XGBoost (SQLi, XSS, traversal, command injection, SSTI, SSRF, XXE, ...) | `ml/attack_type.py` |
| Attack stage | XGBoost (recon, intrusion, exploitation, data theft) | `ml/stage.py` |
| Next step | Markov chain over attack steps | `ml/next_step.py` |
| Action | Decision tree (block, rate limit, allow), plus one fixed rule: a critical session is always blocked | `ml/defense.py` |
| Fix | k-NN (TF-IDF) over a 24-entry knowledge base (OWASP / CWE) | `ml/knowledge_base.py` |
| Review mark | Isolation Forest (unsupervised). It flags unusual requests and never changes a verdict. | `ml/outliers.py` |
| Why? | The features that pushed the detector, in plain sentences | `ml/explain.py` |

Secrets in the results are replaced with `***` after the models have run, so detection is not affected. That covers passwords, tokens, session ids, card numbers and similar fields (`backend/app/privacy.py`).

---

## Quick start (Windows)

You need Python 3.11. Docker Desktop with WSL2 is needed only for the lab.

```powershell
git clone https://github.com/MOUSTAFA82005/AI-ATTACK-INVESTIGATOR.git
cd AI-ATTACK-INVESTIGATOR
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### 1. Put the models in place

Model files are not in git. Put the frozen v10 set in `models/`:

- `detector.joblib`
- `context.joblib`
- `attack_type.joblib`
- `stage.joblib`
- `block_rules.joblib`
- `next_step.json`

Ask Safi for them, or train them yourself (see [Reproducibility](#reproducibility)). Their SHA-256 hashes are in `results/final_v10/model_hashes.txt`. Without the models the site still starts, but an upload answers 503.

### 2. E-mail settings (optional on your own laptop)

Login and sign-up codes are sent by e-mail. Copy `deploy/mail.env.example` to `config/mail.env` and fill it in. For Gmail, use an **App Password** (16 letters), not your normal password. `config/` is never committed.

To set the password without typing it into a file:

```powershell
python -m backend.app.mailer --set-password          # asks for the password, saves it to config/mail.env
python -m backend.app.mailer you@example.com         # sends a test e-mail
```

Without any e-mail settings the server runs in **console mode**: codes are printed in the server window instead of being sent. This is meant for local testing only. Behind a proxy (`AAI_BEHIND_PROXY=1`), console mode is refused.

### 3. Start the server

```powershell
.venv\Scripts\python.exe -m uvicorn backend.app.main:app
```

- Open http://127.0.0.1:8000, then sign up. The first account works as soon as its e-mail is confirmed.
- http://127.0.0.1:8000/health shows `"model_loaded": true` when the models were found.

### 4. Manage accounts from the server

```powershell
python -m backend.app.auth --help    # create, list, approve, disable, enable, reset-password, set-email, rename, delete
```

Set `AAI_SIGNUP_APPROVAL=1` if new accounts must be approved: `python -m backend.app.auth approve <email>`.

### 5. The lab (only for producing new training or test traffic)

```powershell
cd lab
docker compose up -d                                         # Juice Shop behind Nginx on 127.0.0.1:8080
docker compose -f docker-compose.yml -f docker-compose.extra.yml up -d   # + DVWA, bWAPP, DVNA, VAmPI, DVGA, Mutillidae, WebGoat
```

Access logs are written to `lab/logs/`, which is not committed.

---

## The dashboard and accounts

The site has these pages:

- **Overview:** totals, trend, top attackers.
- **New investigation:** upload a log and choose the sensitive or quiet mode.
- **Investigations:** every saved result, with Summary, Visitors, Requests and Fixes tabs.
- **Attackers:** attackers seen across all logs.
- **Recent.**
- **Notifications.**
- **Search:** press `/` to open it.
- **Account.**

A result can be saved as JSON and opened again later.

Security of the site itself:

**Accounts and login**
- Every account has a user name, an e-mail and a password.
- Logging in takes the password plus a 6-digit code sent by e-mail. The code works once, for 10 minutes, with at most 5 tries.
- Passwords are stored only as salted scrypt hashes. A new password needs 12+ characters, upper and lower case, a number and a symbol, and must not be common or contain the user name.

**Sessions**
- The session cookie is a random token marked `HttpOnly` and `SameSite=Strict`. It is `Secure` over HTTPS.
- A session ends after 8 hours, or after 2 hours without any request.

**Rate limits**
- Per address: 5 failed attempts per minute.
- Per account: 10 failed attempts per 15 minutes, counted from any address.
- At most 5 e-mails to one address per hour.

**No account leaks**
- Signing up with an address that already has an account gets the same answer as a new sign-up. The owner gets an e-mail instead, so nobody can test which addresses have accounts.
- Changing the password needs the current password and an e-mailed code. It also logs out every session and sends the owner a notice.

**Browser protection**
- A strict Content Security Policy: only this site's own files, no inline scripts or styles, no CDN. Fonts are bundled.
- `nosniff`, no framing, `no-referrer`.
- Cross-site requests that change something are refused.
- HSTS over HTTPS.
- Results are never cached by the browser.

**Load limits**
- Uploads are limited to 50 MB.
- Analyses run in worker threads: one per account and two in total.
- Each account keeps at most 500 saved investigations, and only sees its own.
- The API description pages (`/docs`, `/openapi.json`) are off. Set `AAI_API_DOCS=1` to turn them on locally.

**Hosting**
- The `Dockerfile` builds the hosted demo: the code and the frozen models only, no data.
- Set `AAI_BEHIND_PROXY=1` behind one HTTPS proxy.
- `AAI_ADMIN_EMAIL` and `AAI_ADMIN_PASSWORD` create the first account on a host without a console.

---

## Results

All tests below were **preregistered**. The test data was cut and SHA-256 hashed before any model saw it, and each sealed test was run **once**. Nothing was tuned after a sealed result. Every table also reports a **rules-only baseline**: payload rules plus rule-based sessions, as in `eval/rules.py`.

### v10 (final version, tag `v10.0-final-test`)

False alarms on real traffic from sites **never used in training or development**:

| Log | Requests | Rules + rule sessions | v10 payload model | v10 + sessions |
|---|---|---|---|---|
| ClarkNet (unseen site) | 300,000 | 0.0166 | 0.0013 | 0.0046 |
| USask (unseen site) | 300,000 | 0.0015 | 0.0006 | 0.0068 |
| NASA Aug 1995 (same site as training) | 300,000 | 0.0006 | 0.0 | 0.0001 |
| zanbil (same site as training) | 400,000 | 0.0011 | 0.0001 | 0.0001 |

Full table: [`results/final_v10/sealed/SEALED-RESULTS.md`](results/final_v10/sealed/SEALED-RESULTS.md). How to read it: [`READING.md`](results/final_v10/sealed/READING.md).

There is one caveat. ClarkNet and USask have no user-agent field, so the main v10 change (telling visitors apart by browser) was not exercised by this sealed test. The bigger session gains were measured on development logs only and are optimistic.

### v9 (tag `v9.0-final-test`)

These are whole data sources the model never saw. Full table: [`results/final_v9/sealed/SEALED-RESULTS.md`](results/final_v9/sealed/SEALED-RESULTS.md).

| Source | Measure | Rules | v8 | v9 |
|---|---|---|---|---|
| WordPress firewall dataset (ModSec-WP) | SQLi recall | 0.948 | 0.988 | 0.984 |
| | XSS recall | 0.947 | 0.968 | 0.951 |
| | RCE recall | 0.548 | 0.907 | 0.683 |
| | False alarms, payload | 0.128 | 0.401 | 0.128 |
| Indonesian web server logs | False alarms, payload | | 0.466 | 0.0004 |
| Glastopf honeypot | Attacker IPs flagged, payload | 0.099 | 0.218 | 0.115 |

Post-hoc analysis: [`results/final_v9/sealed/ANALYSIS.md`](results/final_v9/sealed/ANALYSIS.md).

### Lab sites and real tools (run7, v8)

The lab covers seven vulnerable apps, plus WebGoat, which was never used in training. Attacks come from real tools: sqlmap, nikto, gobuster, feroxbuster, wfuzz, hydra, medusa and dalfox.

| | ML | Rules |
|---|---|---|
| Attack F1 on the 7 known sites | 0.970 to 0.996 | 0.68 to 0.994 |
| False alarms on normal users | 0 | |

See [`results/final_v8/run7/RUN7-RESULTS.md`](results/final_v8/run7/RUN7-RESULTS.md).

---

## Limitations

We report these plainly. They are also listed in the report.

- **Enumeration (IDOR) on WebGoat is mostly missed.** v8 scored 0.69 against 0.98 for rules. No real labelled enumeration data exists for training.
- **dalfox (XSS scanner):** low recall. Most of its lines are reflection markers and parameter mining, not XSS payloads.
- **RCE recall dropped from v8 to v9** on ModSec-WP (0.907 to 0.683). v10 adds the v8 RCE training rows back. That has not been re-measured on a sealed set.
- **Session false alarms on logs behind a reverse proxy or NAT.** Many users share one IP there. The v10 visitor split helps on development logs, but the sealed test could not confirm it.
- **Next-step accuracy on real attackers cannot be measured.** No public data has labelled multi-step attacks.
- **Known-vulnerable-path probes** (honeypot style) are a signature problem, not a learning problem.
- **Logs without request bodies hide attacks sent in POST bodies.**
- **Sessions live in server memory.** Restarting the server logs everyone out.

---

## Reproducibility

- **Frozen versions are git tags.**
  - `v10.0-final-test` is the final version. `v9.0-final-test` and `v8.0-final-test` are earlier ones.
  - Each `results/final_vN/` folder has a `PREREGISTRATION.md` with its amendments, `hashes.txt` (the sealed data), `model_hashes.txt` (the exact models), the sealed results and the development checks.
  - Training and evaluation logs of v10 are in `results/final_v10/logs/`.
- **Sealed data is never opened** before its single run (`data/sealed/`, not committed).
- **Datasets** are not committed (size and licences). They are listed in the report:
  - CSIC 2010
  - HttpParams
  - SR-BH 2020
  - Glastopf
  - AIT-LDS v1.1
  - ModSec-WP
  - zanbil
  - secrepo
  - NASA
  - ClarkNet
  - USask
  - the Indonesian web server logs
- **Training (v10)**, from `data/processed/`:

  ```powershell
  python -m ml.train_detector --v10
  python -m ml.train_attack_type --srbh-days <SR-BH dev days>
  python -m ml.train_stage --ait-hosts cup,insect
  python -m ml.train_defense
  python -m ml.train_next_step
  ```

  The context model of v10 is the v9 one (`python -m ml.train_context`). The exact days and amendments are in `results/final_v10/PREREGISTRATION.md`.
- **The sealed test:** `python -m eval.v10_sealed_test convert`, then `run --tag v10`, then `report`. It was run once. `convert` checks the hashes first. The steps are in the script's docstring.

---

## Repository layout

```
backend/app/   FastAPI app: log parser, /investigate and /analyze, accounts, e-mail codes, saved results
frontend/      Landing page, login, dashboard (plain JS + CSS, no build step, no CDN)
ml/            Features, models and their training scripts
eval/          Evaluation scripts: rules baseline, preregistered tests, development checks
results/       Preregistrations, hashes and results of every frozen version (final_v8, final_v9, final_v10)
lab/           Docker lab (vulnerable apps behind Nginx) and the traffic generator
notebooks/     Earlier experiments (CSIC baseline, model comparison, SHAP, ...)
tests/         pytest suite
deploy/        Pinned requirements for the hosted demo, e-mail settings template
docs/          Original 10-week plan
data/, models/, config/, var/   Local only (datasets, model files, settings, accounts database); never committed
```

---

## Tests

```powershell
python -m pytest tests
```

There are 250 tests. They cover:

- the parser on every format;
- the features and every model step;
- the API;
- accounts, codes, sessions and rate limits;
- the security headers;
- the masking of secrets.

The account and API tests need no mail server: e-mails are captured in a list.

---

## Team

- Mostafa Safi Mostafa Soliman
- Mostafa El-Hassanein El-Hassanein El-Shaarawy
- Mariam Mohamed Mansour

Instructor: Dr. Sara El-Metwally · TA: Eng. Asmaa Nagib

How we work together: [CONTRIBUTING.md](CONTRIBUTING.md).
