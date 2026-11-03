# Environment the frozen models were trained in

The models in `models.sha256` were trained on 3 Nov 2026 in this environment:

- Python 3.13
- scikit-learn 1.9.1
- xgboost 3.4.1
- pandas 3.0.5
- numpy 2.5.3

Loading them with another XGBoost version prints a serialization warning. The models still work: all 133 tests pass on the team laptop.

The models are not in git. A copy whose hashes match `models.sha256` must be kept with the submission. Retraining with the commands in `DEV-RESULTS.md` gives close models, but they are not byte-identical.
