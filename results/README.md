# Results

One folder per frozen version. Nothing in a folder changes after its sealed test was run.

| Folder | Tag | What is inside |
|---|---|---|
| `final_v8/` | `v8.0-final-test` | Preregistration, dev results, run7 sealed test (7 lab sites + WebGoat, real tools, real logs) |
| `final_v9/` | `v9.0-final-test` | Preregistration with amendments, dev checks (AIT, lab regression, threshold, defence replay), sealed test + post-hoc analysis |
| `final_v10/` | `v10.0-final-test` | Preregistration, dev diagnostics, training and evaluation logs (`logs/`), sealed test + how to read it |
| `final_v11/` | `v11.0-final-test` | Preregistration, dev holdout checks, Biblio-US17 sealed test + post-hoc analysis |
| `final_v12/` | `v12.0-final-test` | Preregistration with amendment, regression on all older sets, secrepo sealed test (15 days, hand labels hashed first) |

`hashes.txt` = SHA-256 of the sealed test data (checked before the run). `model_hashes*.txt` = the exact model files.
Only numbers are stored here. Converted rows and predictions (real log lines) stay in `data/` and are never committed.
