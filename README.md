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

**The whole project on one page** (what it does, how it was tested, every result, hard questions, team): [`docs/PROJECT-SUMMARY.md`](docs/PROJECT-SUMMARY.md).

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
| Known scanner targets | A list of files scanners look for (backups, dumps, config and version-control files), counted only when the site answered 403/404/410. It marks a scan in the session layer, never a payload attack. | `ml/probes.py` |
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

Model files are not in git. Put these in `models/`. v12 retrained nothing: the app's `detector.joblib` is the v11 detector (a copy of `detector_v11.joblib`), and the other files are the frozen v10 set. The v10 detector is kept in `models/v10_backup/`.

- `detector.joblib`
- `context.joblib`
- `attack_type.joblib`
- `stage.joblib`
- `block_rules.joblib`
- `next_step.json`

Ask Safi for them, or train them yourself (see [Reproducibility](#reproducibility)). Their SHA-256 hashes are in `results/final_v12/model_hashes.txt`, the exact files used by the v12 sealed test. Without the models the site still starts, but an upload answers 503.

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

### 6. Log request bodies (recommended for your own server)

Most access logs do not record what a form or API call sent, so attacks inside POST bodies cannot be seen. TALON reads the body whenever the log has it. On Nginx (as a reverse proxy, where it reads the body), add one field at the end of the usual combined line:

```nginx
http {
    log_format combined_body escape=json
        '$remote_addr - - [$time_local] "$request" $status $body_bytes_sent '
        '"$http_referer" "$http_user_agent" "$request_body"';
    access_log /var/log/nginx/access.log combined_body;
}
```

This is the format of the lab (`lab/nginx/`). JSON logs work too: put the body in a `request_body` (or `body`) key. Bodies can hold passwords. TALON replaces them with `***` in its results, but the log file on the server still has them, so keep it readable by administrators only.

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
- **Account:** password change, and **Trusted addresses** (your own IPs or networks, such as an office NAT or your proxy). Visitors from them are still scored and shown but never blocked or rate-limited; detection itself does not change (`backend/app/trusted.py`).

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

### v12 (tag `v12.0-final-test`): real internet traffic, 15 sealed days

v12 = v11 plus three fixes found on real secrepo.com traffic (dev days Nov 2, 12, 17 2026): a broken link in quotes (`%22http://...%22`) is scored again without the link, an IP that changes its browser name on almost every request is one visitor, and known exploit endpoints and HEAD backup-folder guesses count as probes (also when answered 429). No model was retrained. The sealed test is 15 other days of November 2026 of the same site, hashed before anyone opened them; visitors were labelled by hand from the raw lines before any system ran.

| secrepo.com, 15 sealed days | Rules | v11 | v12 |
|---|---|---|---|
| Attacker visitors caught (83) | 0.313 | 0.145 | **0.313** |
| Normal visitors with any alarm (4,208) | 0.0090 (38) | 0.0045 (19) | **0 (0)** |
| Normal visitors blocked | | 19 | **0** |
| Attackers blocked or rate-limited | | 0.133 | **0.301** |

The preregistered rule (caught at least v11 + 0.05, no more normal visitors blocked, normal alarms at most v11 + 0.01) was met: **BETTER**. By size (post-hoc, analysis only): 38 of the 83 attackers sent a single request all day, and v12 caught 2 of them; of attackers with 10 or more requests it caught 19 of 27 (0.70). Only 1 missed attacker sent an attack payload; most sent one request for a random script name (`/fdgq.php`), which no list can know. Full table and post-hoc look at the misses: [`results/final_v12/sealed/SEALED-RESULTS.md`](results/final_v12/sealed/SEALED-RESULTS.md). v12 is the last version (stop rule in the preregistration).

### v11 (tag `v11.0-final-test`): the detector retrained with Biblio-US17

v11 = v10 plus training on [Biblio-US17](#reproducibility), the access log of the University of Seville library (Jan to May 2017). This data has only method, URI, status and size: no client address, browser or body. So v11 changes the **payload detector only**; every other model is the v10 one. The sealed test is June 1 to July 17 2017 of the same server, cut and hashed before anyone opened a file.

| Biblio-US17, Jun-Jul 2017 (sealed) | Rules | v10 (never saw this site) | v11 (trained on Jan-May) |
|---|---|---|---|
| Recall, macro over 567 attack families (headline) | 0.077 | 0.744 | **0.820** |
| False alarms, 1,000,000 normal requests | 0 | 0.00004 | **0** |
| False alarms, requests the signature tools wrongly flagged | 0 | 0.247 | **0.0115** |
| LVL2/3 recall (secondary, never trained on) | 0 | 0.085 | 0.076 |

The preregistered rule ("v11 recall at least v10 + 0.02, no higher false alarms") was met. The v10 row is an **unseen-site** result. The v11 row is a **same-site** result: it shows that v11 learned this site without losing anything elsewhere, not that it is better on new sites. Before the run, v11 also passed every development check: lab sites, SR-BH, zanbil, ClarkNet and USask are unchanged.

Full table: [`results/final_v11/sealed/SEALED-RESULTS.md`](results/final_v11/sealed/SEALED-RESULTS.md). Post-hoc analysis (analysis only): [`ANALYSIS.md`](results/final_v11/sealed/ANALYSIS.md). The whole gain comes from `../` (file access) families. About half of the families all three systems missed are requests for known scanner targets, which led to `ml/probes.py` (added **after** the sealed test, development evidence only: May recall 0.560 to 0.737, no false alarms on ClarkNet, USask or zanbil).

### v10 (tag `v10.0-final-test`)

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
- **Session false alarms on logs behind a reverse proxy or NAT.** Many users share one IP there. The v10 visitor split helps on development logs, but the sealed test could not confirm it. Add such addresses to **Trusted addresses** (Account page): their visitors are still scored and shown, but never blocked or rate-limited.
- **Next-step accuracy on real attackers cannot be measured.** No public data has labelled multi-step attacks.
- **v11 is a same-site result.** Its sealed test is later months of the training site. The evidence for unseen sites is still the v10 sealed test.
- **v12 catches about a third of real attackers on secrepo.com (26 of 83), the same as rules.** Its gain is zero false alarms. One-request probes for random script names cannot be caught from one line.
- **Logs without request bodies hide attacks sent in POST bodies.** Log them as in [Quick start, step 6](#6-log-request-bodies-recommended-for-your-own-server) and TALON reads them.

---

## Reproducibility

- **Frozen versions are git tags.**
  - `v12.0-final-test` is the last version and the app's current one: v11 models plus three code fixes, no retraining. `v11.0-final-test` (v10 + Biblio-US17 detector), `v10.0-final-test`, `v9.0-final-test` and `v8.0-final-test` are earlier ones.
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
  - Biblio-US17 (University of Seville, CC BY-NC-ND 4.0, research use, doi:10.12795/11441/148254). Its licence asks that these be cited:
    - J. E. Díaz-Verdejo, A. Estepa, R. Estepa, G. Madinabeitia, J. Muñoz-Calle. "A methodology for conducting efficient sanitization of HTTP training datasets." *Future Generation Computer Systems* 109, 67-82, 2020. doi:10.1016/j.future.2020.03.033
    - J. E. Díaz-Verdejo, R. Estepa, A. Estepa, J. Muñoz-Calle, G. Madinabeitia. "Biblio-US17: A large real and labeled URI dataset for website modelling towards anomaly-based intrusion detection systems." (DOI pending)
- **Training (v10)**, from `data/processed/`:

  ```powershell
  python -m ml.train_detector --v10
  python -m ml.train_attack_type --srbh-days <SR-BH dev days>
  python -m ml.train_stage --ait-hosts cup,insect
  python -m ml.train_defense
  python -m ml.train_next_step
  ```

  The context model of v10 is the v9 one (`python -m ml.train_context`). The exact days and amendments are in `results/final_v10/PREREGISTRATION.md`.
- **Training (v11 detector):** `python -m eval.v11_convert` (Biblio-US17 development months), then `python -m ml.train_detector --v11 train,holdout --out models/detector_v11.joblib`. Details in `results/final_v11/PREREGISTRATION.md`.
- **The sealed tests:** v10: `python -m eval.v10_sealed_test convert`, then `run --tag v10`, then `report`. v11: `python -m eval.v11_sealed_test convert`, then `run`. v12: `python -m eval.v12_label` (labels first), then `python -m eval.v12_sealed_test run --tag v12`, then `report`. Each was run once. `convert` checks the hashes first. The steps are in the scripts' docstrings.

---

## Repository layout

```
backend/app/   FastAPI app: log parser, /investigate and /analyze, accounts, e-mail codes, saved results
frontend/      Landing page, login, dashboard (plain JS + CSS, no build step, no CDN)
ml/            Features, models and their training scripts
eval/          Evaluation scripts: rules baseline, preregistered tests, development checks (index in eval/README.md)
results/       Preregistrations, hashes and results of every frozen version (final_v8 to final_v12)
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

There are 280 tests. They cover:

- the parser on every format;
- the features and every model step;
- the API;
- accounts, codes, sessions and rate limits;
- the security headers;
- the masking of secrets.

The account and API tests need no mail server: e-mails are captured in a list.

---

## Team

- **Mostafa Safi Mostafa Soliman**: the data (datasets, conversion, labels), the models and their training, and the frontend (dashboard and landing page).
- **Mostafa El-Hassanein El-Hassanein El-Shaarawy**: running the tests, the Docker lab and the traffic generator.
- **Mariam Mohamed Mansour**: the backend (FastAPI server and the investigation API).

Instructor: Dr. Sara El-Metwally · TA: Eng. Asmaa Nagib

How we work together: [CONTRIBUTING.md](CONTRIBUTING.md).
