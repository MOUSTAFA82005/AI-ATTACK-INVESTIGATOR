# v11 preregistration (written 2026-11-21 ~04:35Z, BEFORE anyone opened a Biblio-US17 data file)

v10 stays frozen at tag `v10.0-final-test` and stays the reported result for unseen sites.
v11 = v10 + training on Biblio-US17 (University of Seville library web server, Jan 1 - Jul 17 2017).
Only README.en and the folder/file listing were read before this file was written.

## Data and the cut (done 2026-11-21 04:30Z, by file date only)
- Biblio-US17 gives METHOD, URI (path + query), protocol, status and size per request. No client IP, no user agent,
  no body. So v11 can only change the PAYLOAD layer (is this request an attack?). Sessions, behaviour, next step and
  defence cannot be trained or tested on it.
- Daily files `biblio-2017-MM-DD.<ext>` in 5 sets: raw, clean (normal after sanitisation), attack (LVL1 = undoubted
  attacks), labels, sid.
- SEALED TEST = every file dated 2017-06-01 .. 2017-07-17 (47 days, all 5 sets), moved to `data/sealed/v11/biblio/`
  and SHA-256 hashed (`results/final_v11/hashes.txt`) before any use. Never opened, counted or previewed until the
  single run.
- DEV = 2017-01-01 .. 2017-05-31 (151 days). Training uses Jan 1 - Apr 30. May 1-31 is the dev holdout for every
  choice (features, sampling, threshold check). The final v11 model is trained on Jan 1 - May 31 after all choices
  are fixed.

## Labels
- Attack = rows of the `attack` set (LVL1, undoubted).
- Normal = rows of the `clean` set.
- Not used for training or headline numbers: LVL2-4 (context dependent, percent-encoding, DoS), SIDS false positives,
  out-of-specification rows. LVL2-4 recall is reported as a secondary row.
- Known bias (stated in the report): labels start from signature detectors (Snort, Nemesida, ModSecurity CRS) plus
  manual review. Attacks that no signature caught stay in `clean`, so recall is "recall on signature-confirmed attacks"
  and false alarms on `clean` are an upper bound.

## Counting
- Attacks are deduplicated by (method, URI) before counting, because a few repeated requests dominate the raw counts
  (README: 327,906 LVL1 in RAW vs 1,148 after CR<300 filtering). Raw-weighted numbers are reported beside them.
- Normal: a uniform random sample of 1,000,000 `clean` rows (seed 11) for false alarms; unique-URI FA is reported too.

## Systems compared on the sealed part (same converted rows)
1. payload rules (`eval/rules.py`), 2. frozen v10 (never saw Biblio: this row is an UNSEEN-SITE result),
3. v11 (trained on earlier months of the same site: SAME-SITE, secondary, like SR-BH).
Threshold 0.7 (sensitive) as preregistered for v9/v10; 0.8 as a sensitivity row.

## Headline and pre-stated reading
- Headline: attack recall (dedup) and FA on clean, for rules, v10, v11.
- v11 is called better on Biblio if recall(v11) >= recall(v10) + 0.02 AND FA(v11) <= FA(v10).
- v11 is adopted for the app only if ALSO, on dev: lab regression (`eval/v9_lab_regression.py`) attack recall drops by
  at most 0.02 on every site with no rise in normal-user FA; SR-BH holdout recall drops by at most 0.03; payload FA on
  the v10 sealed logs (now dev) does not rise by more than 0.001. Otherwise v10 stays the app model and v11 is reported
  only as a same-site result.
- This test says nothing new about unseen sites for v11. Site independence evidence stays the v10 sealed test.

## Run once
`eval/v11_sealed_test.py` (to be written on dev data only): hash check, convert, run rules/v10/v11, report to
`results/final_v11/sealed/SEALED-RESULTS.md`. Run once at tag `v11.0-final-test`. No changes after the run.

## Licence
CC BY-NC-ND 4.0, research use, the two papers in README.en must be cited. Data is never committed.

## Amendment 1 (2026-11-21 ~05:00Z, from DEV data only; the sealed part is still unopened)
Dev finding (May holdout, v10): 16,541 of 17,166 unique LVL1 attacks in May are one burst of very long, recursively
double-encoded URIs under /salud/noticias (mojibake from a broken client). Per-unique-URI recall (v10 .972 vs rules .018)
is therefore dominated by one pattern and says little. Changes, fixed now:
1. HEADLINE recall = macro recall over attack FAMILIES. Family key = method + first two path segments of the path without
   query, with every run of percent-escapes replaced by "%" and every digit run by "0", cut to 50 characters
   (`eval/v11_dev_eval.py: family()`). Each family counts once. Per-unique-URI and raw-weighted recall stay as secondary rows.
2. A harder normal set is added: rows the signature tools flagged but the dataset authors judged NOT an attack
   (labels ManualTP = 0, "false positive"). FA on this set is reported beside FA on the clean sample.
3. The adoption rule for v11 uses the macro family recall: v11 >= v10 + 0.02, and FA (clean and false-positive set)
   not higher than v10.
Dev numbers that led to this (May): macro family recall v10 .334, rules .210; Jan-Apr v10 .224, rules .221.
v10 misses every family that starts with "/../" (dot-segment paths, labelled LVL1); rules catch them all.

## Freeze note (2026-11-21 ~05:30Z, before the sealed run; the sealed part is still unopened)
- Final v11 detector: `python -m ml.train_detector --v11 train,holdout --out models/detector_v11.joblib`, trained on
  the laptop (xgboost 3.2.0) so the frozen file loads where the sealed data lives. Dev checks before it used the same
  command in the cloud (xgboost 3.4.1); the laptop model was re-checked: ClarkNet payload FA .00131 -> .00132, USask
  .00060 -> .00060 (limit +0.001).
- Dev checks (May holdout, model trained Jan-Apr): macro family recall v11 .560 vs v10 .334 vs rules .210; FA clean 0
  for all; FA on signature false positives v11 .117 vs v10 .228. SR-BH held-out days (holdout-trained pair): recall
  .665 -> .666, FA .014 -> .0139; zanbil 3.0-3.2M FA .00026 -> .00030 (8 more of 200,000; disclosed).
- Lab regression (final laptop model vs final_v10): site recall within +-0.001, normal-user FA 0 everywhere, type,
  stage and defence unchanged. Tools: every row unchanged except dalfox on bWAPP .089 -> .054 (2 of 56 requests;
  disclosed, dalfox is a known Limitation).
- Only the detector changes (Biblio-US17 has no IP, user agent or body). context, attack_type, stage, block_rules and
  next_step stay the frozen v10 files.
- Sealed run: `python -m eval.v11_sealed_test convert`, then `python -m eval.v11_sealed_test run`, once.
