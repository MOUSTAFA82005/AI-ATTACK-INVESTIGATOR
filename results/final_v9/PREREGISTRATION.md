# v9 preregistration: real attacks and real normal traffic

Written 2026-11-04, BEFORE any model (v8 or v9) has been run on any of the new data below.
What was looked at before writing this: column names of SR-BH and ModSec-WP, the count of SR-BH
requests per day (timestamp column only, to choose the split), and the structure/pattern counts of
the Glastopf honeypot (2026-11-03). No request contents, labels or label counts of the new data were read.

## 1. Why
run7 showed the behaviour model learned the style of our own traffic generator (WebGoat enumeration 0%,
dalfox XSS 2-9%). v9 trains on attacks and normal traffic made by other people, and is tested on
whole sources it never saw. run7 (v8) stays in the report unchanged.

## 2. Data and split (fixed now, never changed after a model sees the data)

| Source | Who made it | Labels | TRAIN / DEV | SEALED TEST |
|---|---|---|---|---|
| CSIC 2010 | other team | dataset labels | all (as before) | - |
| SR-BH 2020 (WordPress honeypot, real internet) | real attackers + users | ModSecurity CRS 3.3.0, 14 CAPEC columns | 17-24 Jul 2020 (~596k requests) | 25-29 Jul 2020 + 01 Nov (~306k requests) |
| Glastopf honeypot (secrepo, 2014-15) | real attackers | none needed (honeypot: all traffic is attack) | 2014-09-01 .. 2015-03-31 | 2015-04-01 .. 2015-07-31 |
| ModSec-WP (WordPress testbed, real CVE exploits) | other team | from their attack scripts, 6 classes | - | ALL (whole source unseen) |
| zanbil (real shop, normal) | real users | treated as normal | lines 1-200k and 3,000,001-3,200,000 (old dev) | lines 9,000,001-9,200,000 already USED in run7 -> new unseen slice 10,000,001-10,200,000 (7.0-7.2M = v5 test and 9.0-9.2M = run7 are USED; file has 10,365,152 lines, counted 2026-11-04) |
| secrepo access days (real site, normal) | real users | treated as normal | days already used as dev | 5 run7 days = USED, not reused |
| NASA 1995 (normal) | real users | treated as normal | all | - |
| Charles University log (normal) | real users | treated as normal | - | ALL. Same rule: hashed before any v9 training, else dropped |
| Indonesian web server logs 2025, ModSecurity 30-day 2025 | real attackers | own rules / CRS | - | ALL. Decided 2026-11-04: downloaded and hashed BEFORE any v9 training; if a download fails, the source is dropped and this is written as an amendment |
| Lab runs (run3..run7, camp7) | us | exact | sessions/stage/next-step only | (run7 already reported) |

Rules for the split:
- Sealed files get a SHA-256 hash right after download/cut, before anything else. Hashes go in results/final_v9/hashes.txt.
- Sealed files are never opened, counted, previewed or used for tuning. Any accidental peek is written here as an amendment.
- ModSec-WP: the WAF output columns (action, action_phase, action_message, message_*, full_message_line) are deleted
  at load time; they contain the rule that fired = the answer.
- SR-BH: the 14 CAPEC columns are labels only, never features.

## 3. What is measured at the sealed test (once)
Every number is reported for: rules baseline, v8 (frozen, tag v8.0-final-test), v9.

Headline numbers (labels NOT made by ModSecurity CRS, so not circular):
1. Glastopf sealed months: share of requests flagged, and share of attacker IPs flagged.
2. ModSec-WP: recall per class (sqli, xss, fileinclusion, rce, bruteforce), false alarms on its normal class,
   attack-type accuracy.
3. Real normal traffic (zanbil new slice, Charles, Indonesian benign part): share of requests flagged = false alarm rate.

Secondary numbers (CRS-labelled, reported as "agreement with ModSecurity CRS", not as accuracy):
4. SR-BH sealed days: recall / precision vs CRS labels, per CAPEC class, incl. 16 Dictionary-based Password Attack (brute force).
5. ModSecurity 30-day (if downloaded): share flagged.

## 4. Known limits written now
- CRS labels contain CRS mistakes; training on SR-BH partly teaches the model CRS.
- Glastopf has no status and no size; session rules that need them cannot fire there.
- No public dataset has attacker sessions labelled with stage / next step; those stay measured on the lab runs only.
- Honeypots attract mostly scanners; payload attacks are a minority there.
- SR-BH (train) and ModSec-WP (test) are both WordPress sites: ModSec-WP is a new source, not a new kind of site.
  Other site kinds in the test: Glastopf honeypot, zanbil (shop), Charles (university).
- SR-BH sealed days come from the same site as its training days, so they are a secondary number only.

## 5. Process
1. Hash the sealed parts (now).
2. Convert all sources to the pipeline format (ip, timestamp, method, path, status, size, user_agent, body).
3. Train v9 on TRAIN/DEV only. Tune only on DEV. Compare v8 / v9 / rules on DEV.
4. Commit, tag v9.0-final-test, run the sealed test ONCE, report whatever comes out. Losses are not fixed and re-run.

## Sealing record (2026-11-04)
Done before any model run. eval/v9_seal.py (SR-BH and Glastopf cut by date; whole sources moved) + docker sed for the zanbil slice.
Downloads checked against zenodo MD5. SR-BH dev rows 596,053 (2 rows without timestamp dropped from both parts), Glastopf dev events 4,334.
Hashes: results/final_v9/hashes.txt (7 files incl. zanbil_v9.log). Sealed folder: data/sealed/v9/ (git-ignored).
Not obtained before training, so dropped from the sealed test: Charles University log (still downloading). If it arrives later it may only be used as an extra, clearly labelled not-preregistered check.

## Amendments
### Amendment 1 (2026-11-04, before any model run)
While writing the converter, the first DEV Glastopf record was seen to be a plain stylesheet request (pattern style_css).
So "all honeypot traffic is attack" is not true per request: crawlers and bots also hit the honeypot.
Change: for Glastopf the headline number is per IP (share of source IPs with at least one flagged request);
the per-request share flagged is reported as secondary. Nothing else changes.

### Amendment 2 (2026-11-04, before any model run)
Converting SR-BH DEV gave 382,619 attack rows and 213,434 normal rows. The SR-BH paper reports 382,619 malicious
and 525,195 normal requests in total. By subtraction (no sealed file was opened), the sealed SR-BH days hold no or
almost no CRS-labelled attacks: about 311,761 normal requests. So the SR-BH sealed part is a false-alarm test on real
normal traffic of a site seen in training, not an attack test. Change: section 3 item 4 becomes "SR-BH sealed days:
share of normal requests flagged (false alarms)". Attack recall vs CRS labels is measured on DEV only (cross-validation
by day), and reported as dev, not as a test result.
Also noted: SR-BH DEV attacks are dominated by SQL injection (250,311 rows, 65%); brute force has only 1,847 rows.

### Amendment 3 (2026-11-04, before any v9 training)
Running frozen v8 on SR-BH DEV showed that every SR-BH DEV request has the same source IP (one address for all
596,053 rows; the honeypot sat behind a gateway or the IPs were replaced). Sessions are built per IP, so on SR-BH a
whole day is one "session", and the session layer marks every request of a day once any attack appears.
Change: SR-BH is evaluated PER REQUEST only (payload model vs payload rules), never with sessions, at dev and at the
sealed test (section 3 item 4: share of normal requests flagged by the payload model and by the payload rules).
SR-BH cannot be used to train or test anything session-based (behaviour model, stage, next step).


### Amendment 4 (2026-11-04, before any final v9 training): extra TRAINING/DEV sources
Added for training and dev only (the sealed test does not change): AIT Log Data Set v1.1 (zenodo 4264796, testbed by
another team: nmap, nikto, account enumeration, hydra brute force, webshell upload, privilege escalation, Apache access
logs labelled per line) for the stage model, the next-step model and brute force; and sweetie-data tanner web honeypot
(2020, real IPs) for scanning. Real attacker sequences (Glastopf/tanner DEV, per IP) are also used to check the
next-step model and to replay the defence ("how many later attack requests would a block have stopped").
Also added as a dev change: served login/admin pages are not payload alarms (ml/detector.py, see dev_v8_findings.md).
What was used in the end (dev, 2026-11-04): AIT hosts cup and insect train the behaviour and stage models, onion and
spiral are the dev check (eval/v9_ait_eval.py, eval/v9_defence_replay.py). tanner and Glastopf were NOT used for
training: they have no per-request truth and most visitors send one request (Glastopf DEV: 1,027 of the 1,280 requests
missed by the pipeline are visits to "/"); they stay dev/test sources only. Real multi-step attacker sequences were
checked three ways (Glastopf's own request classes: 8 of 882 IPs with 2+ steps; our pipeline per IP: 3; tanner: 1 of
566), too few to train or measure the next-step model, so it stays trained on lab campaigns (Limitation).

### Amendment 5 (2026-11-04, before any final v9 training and before the sealed test): detector threshold
The payload detector's threshold was 0.5, never chosen. It is chosen on DEV data by a rule written down BEFORE the
curve was seen (told to the team in chat at 04:38Z): the threshold with the lowest SR-BH "FA other" (false alarms on
CRS-normal requests that are not probe-like), such that SR-BH recall >= recall at 0.5 minus 0.03 and lab run7 payload
recall >= 0.98; ties go to the value closest to 0.5. Curve (eval/v9_threshold.py, detector_v9_holdout2, SR-BH days
19/23/24 Jul): 0.3 to 0.7 keep recall .668-.663 with FA .0166-.0139; 0.8 drops FA to .0005 but recall to .599 and
Glastopf IPs flagged from .193 to .101, so it fails the recall condition. The rule gives 0.7 (ml/detector.py
DETECTOR_THRESHOLD, used by eval/final_test.py and the backend). 0.8 is reported as a sensitivity row, not used.
The behaviour model's payload_score feature keeps 0.5, the value it was trained with. The final models (trained on all
DEV days) use 0.7, chosen with the held-out model: the final model's calibration can differ slightly.
