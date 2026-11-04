# v10 preregistration (written 2026-11-04 ~07:45Z, BEFORE any v10 code change and before the v10 test data exist on disk)

v9 stays the reported result (sealed test run once, results/final_v9/sealed/SEALED-RESULTS.md).
v10 is a new version with a new sealed test. Everything used by the v9 sealed test is DEV data for v10
(Indonesian Web Server Log Dataset, ModSec-WP, owasp, SR-BH sealed days, Glastopf sealed, zanbil 10.0-10.2M).
That dev use is stated in the report.

## What v10 tries to fix (from the v9 sealed test and its post-hoc analysis)
1. Session layer false alarms on real traffic (v9: .216/.367 on the two Indonesian sites with real client IPs, .585 on ModSec-WP).
   Allowed: (a) mark a log or an IP as "shared address / proxy" and stop per-IP behaviour verdicts there (report it as
   "sessions unreliable" instead), (b) more real normal visitors in the context model training (dev sources only),
   (c) changes to behaviour rules in ml/sessions.py. Not allowed: per-site thresholds.
2. WordPress login shortcut (payload model flags 98.8% of normal wp-login POSTs on ModSec-WP).
   Allowed: normal login POSTs as normal rows in detector training (dev sources only).
3. RCE recall (ModSec-WP rce .683 in v9 vs .907 in v8): bring back the RCE / command-injection training rows of v8.
4. Optional, only if 1-3 are done: probes of well-known vulnerable paths (Glastopf), from public path lists.
Not touched (stay Limitations): WebGoat enumeration, dalfox, WebGoat exploitation stage, next-step accuracy.

## Rule for adopting a change (on DEV only)
A change is kept only if, on dev: the targeted number improves; lab regression (eval/v9_lab_regression.py) attack recall drops
by at most 0.02 on every site and normal-user FA does not rise; AIT dev hosts (onion, spiral) scan and hydra recall do not drop;
SR-BH holdout payload recall drops by at most 0.03. Detector threshold stays 0.7 (sensitive) / 0.8 (quiet).

## Sealed v10 test (fixed now; downloaded / cut and SHA-256 hashed before any use; never opened, counted or previewed)
| id | source | what | role |
|---|---|---|---|
| S1 | ClarkNet (ita.ee.lbl.gov clarknet_access_log_Aug28.gz) | first 300,000 parsed requests | UNSEEN site, real client hosts, normal traffic: session + payload FA (headline) |
| S2 | USask (ita.ee.lbl.gov usask_access_log.gz) | first 300,000 parsed requests | UNSEEN site, same as S1 (headline) |
| S3 | NASA KSC Aug 1995 (ita.ee.lbl.gov NASA_access_log_Aug95.gz) | first 300,000 parsed requests | same site as training (NASA Jul 1995): secondary |
| S4 | zanbil lines 5,000,001-5,200,000 and 8,000,001-8,200,000 | 2 x 200,000 lines | same site as training: secondary |
| S5 | secrepo.com access logs 2026-10-25, -26, -27, -29, -30, -31 (all days listed after 2026-10-24) | all lines | same site as dev days; real scanners unlabelled: flagged share vs rules, secondary |
| S6 | lab, new generator seed 10010, all lab sites + WebGoat (only if the lab starts on the laptop) | generated | regression of attack recall incl. cmdi / RCE |

Labels: S1-S4 have no attack labels; all requests are counted as normal except those the payload rules call attacks
(those are reported separately, not as FA). S5 same. S6 labelled by the generator.

## Metrics (same definitions as the v9 sealed test, eval/v9_sealed_test.py)
- Payload FA = share of normal requests flagged by the payload detector.
- Session FA = share of normal requests in sessions flagged by the session layer ("model + sessions").
- If a log/IP is marked "shared address", its requests count as NOT flagged by sessions, and the share of requests
  marked so is reported next to the FA (so the mark cannot hide alarms silently).
- S6: per-family recall (sqli, xss, cmdi/rce, traversal, ...), normal-user FA, WebGoat numbers.
- Every table: v10, v9 (frozen, tag v9.0-final-test) and rules.

## Pre-stated reading
v10 counts as better on sessions only if its session FA is lower than v9 on BOTH S1 and S2 and S6 attacker recall
drops by at most 0.02. Any other outcome is reported as it is. The v10 sealed test runs once.
No WordPress-login test data with bodies is available unseen: the login fix is shown on DEV only (stated as such).

## Amendment 1 (2026-11-04 ~08:30Z, after the DEV diagnosis, before any v10 model is trained; no v10 sealed file opened)
Dev diagnosis (results/final_v10/dev/SESSION_DIAG.md, PAYLOAD_DIAG.md, v9 models):
- Proxy logs: the IP with 97-360 user agents carries 94-96% of requests and all session false alarms; other IPs 0.
  -> change 1a: one visitor = IP + user agent (ml/sessions.py visitor_key), used for sessions and page popularity.
- ModSec-WP records no answer size (size 0 on 100% of 2xx), so every page shares one "200:0" answer = scanner look.
  -> change 1b: when >= 90% of 2xx answers have no size, a 2xx answer counts as the page's own answer.
- The two real-IP Indonesian sites: one answers 404 to 99.9% of requests (site gone), the other 404/503 to ~50%.
  Their "normal" label only means no YAML rule matched; not changed (reported as a label caveat).
- WordPress login shortcut: normal wp-login POST bodies fire p_probe_path + v_kw_ssrf (redirect_to=http...wp-admin).
- RCE: v9 keeps all v8 training rows, so "bring back v8 rows" (change 3) is void. Missed RCE rows are mostly path-only
  probes (p_probe_path, v_kw_cmd). Changes 2+3 become ONE change: train on half 0 of ModSec-WP (a fixed hash of the
  distinct request): all normal rows + capped payload attacks (rce 2,500, xss/fi/sqli 1,500 each).
  Half 1 is the dev check. ModSec-WP's time order cannot be used (all RCE/XSS/normal rows are in the second half of time).
  The RCE and login gains are therefore SAME-SITE dev numbers only; the v10 sealed test measures only that they do not
  add false alarms on unseen sites (S1-S5) and do not lower lab recall (S6).
- Change 4 (known-vuln paths) is dropped for time.
