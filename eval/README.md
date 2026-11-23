# Evaluation scripts

Run every script from the repository root as a module, for example `python -m eval.rules`. Each script's docstring gives its exact commands.
The scripts stay in one flat folder on purpose: the preregistrations and results cite them by these paths.

**Sealed** scripts were run once, at their freeze tag. **Dev** scripts read development data only and never open `data/sealed/`.

## Shared

| Script | What it does |
|---|---|
| `rules.py` | The rules-only baseline used in every results table (keyword patterns, no learning) |
| `final_test.py` | The full pipeline on one labelled run, exactly as the backend uses it |
| `match_labels.py` | Joins the lab generator's labels to the Nginx log lines |
| `threshold_check.py` | Why the session-layer thresholds are where they are (table for the report) |
| `benign_tricky.py`, `benign_tricky_new.py` | Normal input that looks like an attack to a naive rule (false-alarm checks) |

## v8 (`results/final_v8/`)

| Script | Kind | What it does |
|---|---|---|
| `run7_final.py` | Sealed | run7: the final test of the v8 models (7 lab sites, WebGoat, real tools, real logs) |
| `run7_precision.py` | Sealed | Hand-labelled precision on blind samples of run7 |

## v9 (`results/final_v9/`)

| Script | Kind | What it does |
|---|---|---|
| `v9_seal.py` | Sealing | Cuts and hashes the sealed parts of SR-BH and Glastopf |
| `v9_convert.py`, `v9_convert_ait.py` | Dev | Convert the external datasets and AIT-LDS to the pipeline format |
| `v9_baseline.py` | Dev | The frozen v8 pipeline and the rules on the new development data |
| `v9_dev_eval.py`, `v9_fa_look.py` | Dev | Payload detectors per request, and a look at their false alarms |
| `v9_threshold.py` | Dev | Picks the detector threshold (0.7) by a rule stated before the results |
| `v9_type_eval.py` | Dev | Attack type against the CRS labels of SR-BH |
| `v9_ait_eval.py`, `v9_defence_replay.py` | Dev | AIT-LDS hosts kept out of training: pipeline, stage and defence replay |
| `v9_lab_regression.py` | Dev | Re-runs the run7 lab sites with the current code |
| `v9_sealed_test.py` | Sealed | The v9 sealed test |
| `v9_sealed_analysis.py` | Analysis | Post-hoc look at the v9 sealed result (changes nothing) |

## v10 (`results/final_v10/`)

| Script | Kind | What it does |
|---|---|---|
| `v10_payload_dev.py`, `v10_payload_diag.py` | Dev | Payload detector checks on data the v9 sealed test had opened |
| `v10_session_diag.py`, `v10_ait_ua_diag.py` | Dev | Session false alarms and the visitor (IP + browser) split |
| `v10_sealed_test.py` | Sealed | The v10 sealed test (ClarkNet, USask, NASA, zanbil, secrepo) |

## v11 (`results/final_v11/`)

| Script | Kind | What it does |
|---|---|---|
| `v11_convert.py`, `v11_dev_eval.py` | Dev | Biblio-US17 development months |
| `v11_fa_check.py` | Dev | False alarms on the v10 sealed logs (development data for v11) |
| `v11_sealed_test.py` | Sealed | The v11 sealed test (later months of Biblio-US17) |
| `v11_sealed_analysis.py` | Analysis | Post-hoc look at the v11 sealed result (changes nothing) |

## v12 (`results/final_v12/`), the last version

| Script | Kind | What it does |
|---|---|---|
| `v12_regression.py` | Dev | v12 against v11 on every older set (must not get worse) |
| `v12_label.py` | Sealed | Labels each visitor of the 15 sealed days from the raw lines, before any system ran |
| `v12_sealed_test.py` | Sealed | The v12 sealed test (v12, v11 and the rules on 15 unseen secrepo.com days) |
