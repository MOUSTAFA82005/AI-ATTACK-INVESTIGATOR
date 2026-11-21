# v12 pre-registration (written 2026-11-21 14:10Z, before any v12 code)

## Why v12
Review of real, unseen secrepo days 2026-11-02/12/17 (2,292 requests) with v11 found:
- 5 false alarms, all MJ12bot following broken links whose path holds a quoted URL (`"http://..."`), read as SQL injection and blocked.
- ~10 missed attacker visitors: (a) scanners that change user agent on every request (visitor = IP + UA splits them),
  (b) single-request probes of known exploit endpoints (Metabase, UEditor, DedeCMS, webshell names).
v12 fixes only these three things. This is the LAST version (stop rule below).

## Sealed data (hashed before anyone opened it)
secrepo self.logs, 15 days: 2026-11-01, 03-11, 13-16, 18 (days 19-20 were not published yet; 02/12/17 = dev).
Files: data/sealed/v12/*.gz on Safi laptop, sha256 in results/final_v12/hashes.txt
(sha256 of hashes.txt = 657cf5f6768ad7d045a20753df9717503b45df676c9ae14564cdf45cad72b6e0). All 15 pass `gzip -t`.
Nobody opens these files until step 4 below.

## Changes allowed (developed on dev days 02/12/17 only)
1. Quoted-URL re-score: if a flagged request path holds a quoted URL, score it again with the quoted part removed;
   if the new probability is < 0.7 it is not a payload alarm.
2. UA rotation: one IP whose UA changes on >= 80% of its >= 5 requests becomes one visitor (key = IP only).
3. Known exploit endpoints from public lists (nuclei templates / public advisories, sources cited) added to ml/probes.py,
   counted only when the answer is 403/404 (not served).
No retraining of any model. Threshold stays 0.7. Defence tree unchanged.

## Order (fixed)
1. Hash sealed files (done).
2. Implement 1-3 on dev days; tests pass.
3. Regression on all old sets (lab run7, SR-BH holdout, Biblio-US17 test, NASA, ClarkNet, USask, zanbil, secrepo old days):
   v12 must not be worse than v11 on any headline number by more than 0.005 (and 0 new normal visitors blocked).
4. FREEZE: commit + tag v12.0-final-test + model/code hashes. Only after the freeze is any sealed file opened.
5. Label sealed visitors from the raw log by hand, using the label rules below, WITHOUT running v11, v12 or the rules
   baseline. Labels saved + hashed (results/final_v12/labels.csv) before step 6.
6. Run once: v12 vs v11 vs rules on the 15 days. Report as-is.

## Labels (visitor = IP; one label per IP per day)
- attacker: any request that is an exploit payload, a known-vulnerable-path probe, a login brute force (>= 10 failed logins),
  or a scan (>= 20 distinct paths mostly 404, or a known scanner UA).
- normal: everything else, including search-engine crawlers that only follow links.
Ambiguous IPs are marked `unsure` and left out of both rates (count reported).

## Metrics
- attacker IPs caught (any alarm: payload or session at medium+) / attacker IPs
- normal IPs with any alarm / normal IPs ; normal IPs blocked (count)
- attacker IPs blocked or rate-limited

## Pass conditions (stated now)
v12 is "better" if: attacker IPs caught >= v11 + 0.05 AND normal IPs blocked <= v11 AND normal alarm rate <= v11 + 0.01.
Otherwise the result is reported as "no clear gain" and v11 numbers stay the headline; v12 code is still kept only if
regression (step 3) passed.

## Stop rule
No v13. Whatever the sealed result is, after step 6: freeze, report with Limitations, demo. New ideas -> Future work.

## Amendment 1 (2026-11-21 ~14:50Z, during dev work, before the freeze; sealed files still unopened)
Details of the three changes as built on the dev days (the plan above gave first guesses):
- UA rotation rule is "one IP with >= 4 different agents (digits removed) and at least one agent per 2.5 requests"
  (not "80% of >= 5"): the dev scanners rotate the agent every 2 requests (redirect + follow), ratio 0.5.
- 429 (too many requests) now counts as "not served" for every known probe (secrepo answers scanners 429).
- Backup-folder guesses (/backup /bk /bc ...) count only for HEAD requests: the run7 Mutillidae normal users open
  /backup/ with GET (lab regression showed 6 normal-user false alarms with the GET version; removed).
- Quoted-link re-score keeps the LOWER of the two scores and only removes a plain link (letters, digits, . _ ~ / : -).
Dev days result (v11 -> v12): MJ12bot false blocks 5 -> 0; attacker IPs newly flagged 11 (Metabase x5, UEditor x2,
DedeCMS x1, HEAD backup finders x3); still missed: random webshell names (/ysyqq.php), probes answered only 301.
