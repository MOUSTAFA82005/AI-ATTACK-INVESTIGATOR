# AI Attack Investigator: final state of the learned models (dev, 3 Nov 2026)

> **Update v8 (3 Nov, afternoon):** the behaviour model was retrained with one change. Section 8 has the before/after. Sections 2-7 are the v7 numbers, kept for the record.

This file covers the models now on Safi's laptop (`models/`, trained 3 Nov 02:30 UTC). Every number here is **dev**: it comes from data used while building the models, measured with the site, tool or real log left out of training. The final number is run7. Its rules are in `PREREGISTRATION.md`, and none of its data has been opened.

Raw tables: `results/v7/` (`loso_loto.csv`, `real_logs.csv`, `detector_hand_vs_cnn.csv`). Scripts: `scripts/v7/`.

## 1. What each model learns (and what is still a rule)

| Part | Model | Input | Trained on |
|---|---|---|---|
| Is this request an attack? | XGBoost (`detector.joblib`) | 60+ features of the request text: keywords, characters, encodings, value shapes, GraphQL arguments, path values | CSIC 2010, HttpParams, new families, lab requests of 7 sites, 60k real zanbil requests |
| What is this client doing? | XGBoost, 4 classes: normal / brute force / enumeration / scan (`context.joblib`) | 16 features that mean the same on any site: how popular the page is, how many answers the site gives, attempts on one form, values only this client sends, share of unpopular pages... No URL, no site name. | 7 lab sites + 12 real tools on all 7 sites + real normal traffic (zanbil, public Apache, NASA 1995, Elastic nginx) |
| Which attack type? | XGBoost (`attack_type.joblib`) | Type features of the request | HttpParams, ECML/PKDD, new families, ffuf |
| Which stage? | XGBoost (`stage.joblib`) | Stage features of the request and its session | Lab runs labelled with the true stage from the server's answer |
| Block / rate limit / allow | Decision tree, depth 4 (`block_rules.joblib`) | Session counts | Lab sessions, labels from the truth |
| Next step | Markov chain (`next_step.json`) | Previous steps | 120 lab campaigns |

**Still rules, stated in the report:** the rules baseline itself (`eval/rules.py` and rule sessions), which is only used for comparison. The WAF rule text written for a blocked session is also rule-based.

## 2. New sites: leave one site out (7 sites)

The model is trained without the site, then tested on that site's generator run and on 12 real tools run against it.

| Site left out | Generator: ML | Generator: rules | Behaviour attacks caught (ML) | Real tools: ML | Real tools: rules | Normal users flagged: ML / rules |
|---|---|---|---|---|---|---|
| bWAPP | 0.989 | 0.977 | 0.984 | 0.999 | 0.962 | 0 / 0 |
| DVGA (GraphQL) | 0.964 | 0.662 | 0.947 | 0.996 | 0.963 | 0 / 0 |
| DVNA | 0.995 | 0.980 | 1.000 | 0.997 | 0.979 | 0 / 0 |
| DVWA | **0.912** | **0.981** | **0.873** | 1.000 | 0.948 | 0 / 0 |
| Juice Shop | 0.996 | 0.981 | 0.996 | 1.000 | 0.927 | 0 / 0 |
| Mutillidae | 0.995 | 0.993 | 0.997 | 0.997 | 0.889 | 0 / **24** |
| VAmPI (REST) | 0.995 | 0.650 | 0.994 | 1.000 | 0.951 | 0 / 0 |

ML beats rules on 6 of 7 sites. It loses on DVWA (see section 6).

## 3. New tools: leave one tool family out (all 7 sites)

| Tool left out | Requests | ML | Rules |
|---|---|---|---|
| dirb | 20,199 | 1.000 | 0.999 |
| ffuf | 32,298 | 1.000 | 1.000 |
| hydra | 21,795 | 1.000 | 0.933 |
| hydra, slow | 3,869 | 0.958 | 0.839 |
| nikto | 44,021 | 1.000 | 0.980 |
| nikto, evasion | 723 | 0.929 | 0.876 |
| nmap http scripts | 12,403 | 1.000 | 0.990 |
| sqlmap | 771 | 0.960 | 0.918 |
| sqlmap, tamper | 8,402 | 0.985 | 0.609 |
| wapiti | 9,293 | 0.859 | 0.758 |
| whatweb | 51 | 0.686 | 0.647 |

- **Normal users flagged:** ML flagged none in any run. Rules flagged 24 Mutillidae users in each run.
- **Not used:** gobuster, wfuzz, medusa, dalfox and feroxbuster were never run. They are kept for run7.

## 4. Real traffic

The share of requests flagged. "Left out" means the model was retrained without that log, so the number is what an unseen real site of that kind would get. The delivered model is trained with all three logs.

| Log | Requests | ML flagged | Rules flagged | Note |
|---|---|---|---|---|
| Public Apache (left out) | 9,999 | 0.45% | 0.16% | |
| NASA July 1995 (left out) | 400,000 | 0.07% | 0% | |
| Elastic nginx (left out) | 51,462 | **43.4%** | 0% | Weak spot, see section 6. |
| zanbil (dev slice) | 200,000 | 0.03% | 0.46% | |
| secrepo 2020-06-16 | 14,288 | 86.5% | 89.8% | 9 clients send injected markup (`"><a ...`) in every request. Under the hand-labelling rules in section 4 of the preregistration, that markup counts as an attack. |
| secrepo 2024-10-04 | 47,392 | 0.70% | 0.89% | |
| secrepo 2025-03-02 | 88,543 | 1.67% | 55.5% | Rules flag a normal feed reader. |

**Hand labelling (dev).** Random samples of flagged requests are in `results/v7/hand_label_samples/`, up to 200 per log. They still show the model's verdict, so they can only be used for dev labelling. For run7, the samples are drawn blind, as `PREREGISTRATION.md` requires.

## 5. Tried and rejected (reported, not hidden)

- **Character CNN instead of hand features for the detector.** It was tested leaving one site out each time.
  - It missed 18% of Juice Shop attacks (hand features: 0.4%) and 21% of VAmPI attacks (hand: 3%).
  - On held-out sites it gave 175 false alarms on Juice Shop and 142 on DVGA (hand features: 17 and 0).
  - It gave 50 alarms on the tricky benign set (hand: 4) and flagged 2.45% of public Apache traffic (hand: 0.65%).
  - It did catch more nikto requests, 0.95 against 0.30. That gap does not matter, because the behaviour model catches nikto (1.0).
  - Averaging the CNN with the hand detector was no better: DVGA 142 false alarms, public Apache 2.98%.
  - Decision: keep the hand-feature detector. The CNN code and results are kept, in `scripts/v7/det3_exp.py` and `results/v7/detector_hand_vs_cnn.csv`.
- **Learning from lab data only** (earlier v6). It flagged 30% of real zanbil traffic. This is why real normal logs and real tools are now in training.
- **"Answer pages seen publicly" feature.** It made held-out sites worse, so it was removed.

## 6. Holes found by these tests, and the general fix for each

| Hole | Fix (general, not one case) | Effect |
|---|---|---|
| hydra page loads labelled as brute force | Only requests that send a password are labelled brute force. | Mutillidae normal-user false alarms 3,598 → 0 |
| GraphQL brackets hid the values | A GraphQL parser: string literals are masked first, and every argument is read as a value (`ml/graphql.py`). | DVGA sqlmap-tamper 0.14 → 0.80 (detector alone) |
| REST payloads inside the path were invisible | Path segments containing code characters are read as values (`features.path_values`). | VAmPI 0.002 → 0.99 |
| `.gz` and `.log` downloads flagged on a real site | The file-extension feature was removed from the detector. | secrepo false flags gone |
| `index.php?page=x` routing looked like one page | Query values that 3+ visitors share and that look like page names are part of the page. | Mutillidae fixed, DVWA unchanged |
| CSRF tokens made every login look unique | Random tokens are ignored when comparing what a client sends. | DVWA login attempts are counted as repeats again |
| sqlmap page loads labelled as a scan | Only the requests that send values are labelled. | nginx false alarms 4% → 0 |

## 7. Weak spots that remain (with numbers)

1. **Unfamiliar real traffic, Elastic nginx left out: 43% flagged as scan.**
   - The log is thousands of package-manager clients, each asking for 2–3 URLs and getting 404. That shape is close to a small scan, and the model is unsure: probability about 0.51.
   - With nginx in training (the delivered model), the shape is learned.
   - What this shows is that a new kind of real site can still produce false alarms. Nothing was tuned on this number.
2. **DVWA left out: 0.912 against rules 0.981.** DVWA's brute-force page sends the password in a GET query. The other sites send it in a POST body, so the model has not seen this case without DVWA (behaviour 0.873).
3. **wapiti 0.859 and whatweb 0.686.** These tools send few requests per site (whatweb 1–18). With so few requests there is little behaviour to learn from.
4. **A user who mistypes a password on a login form nobody else uses** can be flagged as a small probe. On a real site other people log in, and then it is not flagged (test `test_a_user_who_mistypes_twice_is_not_a_brute_force`).
5. **Juice Shop feedback text such as "<48h"** gives 17 detector false alarms out of 6,878 normal requests.
6. **Next step:** top-1 is at most 0.38, because the generator picks the next step at random.
7. **All attacks come from our own generator or from real tools run in our lab.** Real-world recall can only be estimated from the hand-labelled flags. The unflagged real requests are never labelled, so recall on real traffic cannot be measured.

## 8. v8: scans and ID sweeps inside normal browsing (3 Nov, afternoon)

- **The change:** every lab scan and enumeration is added once more to training, inside a copy of one normal visitor's browsing, from one new address (`train_context.mixed_copies`).
- **Why:** the model had learned that a scan is "a session that does nothing else". That is a lab habit, not a property of attacks.
- **Variants tried:** three variants were each measured with every site and the nginx log left out (`results/v8/var14_*.txt`):

| Mixed in | nginx left out | DVWA | DVGA | Juice Shop | DVWA normal requests flagged |
|---|---|---|---|---|---|
| nothing (v7) | 43.4% | 0.912 | 0.964 | 0.996 | 0 |
| brute force only | 43.4% | 0.911 | 0.926 | 0.996 | 42 (+462 next to tools) |
| scan only | 8.1% | 0.947 | 0.959 | 0.957 | 3 (+33) |
| **scan + enumeration (kept)** | **5.3%** | **0.937** | **0.973** | **0.973** | **3 (+33)** |

The brute-force variant made a user who logs in again look like a brute force, so brute forces are not mixed in.

**v8, leave one site out (generator run):**

| Site | v7 ML | v8 ML | Rules | Normal requests flagged, v8 (generator + tool runs) |
|---|---|---|---|---|
| bWAPP | 0.989 | 0.983 | 0.977 | 0 |
| DVGA | 0.964 | **0.973** | 0.662 | 0 |
| DVNA | 0.995 | 0.995 | 0.980 | 0 |
| DVWA | 0.912 | **0.937** | 0.981 | 3 + 33 |
| Juice Shop | 0.996 | **0.973** | 0.981 | 0 |
| Mutillidae | 0.995 | 0.996 | 0.993 | 0 (rules: 24 + 240) |
| VAmPI | 0.995 | 0.989 | 0.650 | 0 |

**Leave one tool out, v8:**

- Unchanged or better than v7: hydra-slow 0.958, nikto-evasion 0.985 (v7 0.929), sqlmap-tamper 0.985.
- wapiti 0.859 and whatweb 0.686 are unchanged.
- 0 normal users flagged.

**Real logs, v8:**

| Log | v7 | v8 |
|---|---|---|
| nginx, left out | 43.4% | **5.3%** (449 clients flagged → 8) |
| NASA, left out | 0.07% | 0.06% |
| public Apache, left out | 0.45% | 0.45% |
| zanbil dev | 0.03% | 0.02% |
| secrepo days | 86.5 / 0.70 / 1.67% | same |

**What is still weak:**

1. **ML now loses to rules on 2 of the 7 sites** (v7: 1 of 7):
   - Juice Shop: 0.973 against 0.981.
   - DVWA: 0.937 against 0.981.
   - This was accepted for a ninefold cut in false alarms on an unseen real log, because the project's goal is any real log.
2. **DVWA's GET brute force is still partly missed.** The page is opened by fewer normal visitors than other login pages, and the attacker's session also walks IDs. Mixing brute forces into browsing did not fix it (table above).
3. **New false alarms on DVWA:** 3 normal requests in the generator run, and 33 normal requests across 12 tool runs (DVWA left out).
4. **What I did not fix and why:**
   - **The "<48h" detector false alarms:** a fix would mean writing benign examples that look like that one error, which is fitting to the test.
   - **More real logs from other sites:** the public trace archives are blocked from here.

## 9. Reproduce on the laptop

```
python -m pytest -q                          # 133 tests
python -m ml.train_detector
python -m ml.train_attack_type
python -m ml.train_context data/raw/tools data/raw/zanbil_access.log
python -m ml.train_stage
python -m ml.train_defense
python -m ml.train_next_step
```

- **Data for these commands:** the tool logs are in `data/raw/tools/`. The real normal logs are in `data/raw/` (`public_apache_logs.log`, `nasa_access_jul95.log`, `nginx_elastic.log`, `zanbil_access.log`).
- **Data that is never touched:** `data/sealed` and bak62.
