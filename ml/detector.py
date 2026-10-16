"""
detector.py - the attack-detection model (normal vs attack) for one request.

Shared by the training script and the backend, so both turn a request into
features in exactly the same way.

Model: XGBoost on TF-IDF character n-grams + the hand-built features from
features.py (best combination in notebooks/02_csic_models.ipynb).
"""
from pathlib import Path
from urllib.parse import unquote_plus

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from ml.features import request_features

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "models" / "detector.joblib"


def _decode(s):
    return unquote_plus(str(s or ""), encoding="latin-1")


def to_frame(methods, paths, bodies):
    """Turn lists of (method, path, body) into the table the model expects."""
    methods = [str(m or "GET").upper() for m in methods]
    paths = [str(p or "") for p in paths]
    bodies = [str(b or "") for b in bodies]
    text = [f"{m} {_decode(p)} {_decode(b)}" for m, p, b in zip(methods, paths, bodies)]
    hand = pd.DataFrame([request_features(m, p, b) for m, p, b in zip(methods, paths, bodies)])
    return pd.concat([pd.DataFrame({"text": text}), hand], axis=1)


def build_pipeline(hand_cols, pos_weight=1.0, n_jobs=2, use_tfidf=True):
    """use_tfidf=False gives the features.py-only model (less tied to one site)."""
    parts = [("hand", StandardScaler(), hand_cols)]
    if use_tfidf:
        parts.insert(0, ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(2, 4), min_df=2,
                                                  max_features=2_000, sublinear_tf=True,
                                                  dtype=np.float32), "text"))
    features = ColumnTransformer(parts)
    model = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1, tree_method="hist",
                          max_bin=32, scale_pos_weight=pos_weight, n_jobs=n_jobs,
                          random_state=42, eval_metric="logloss")
    return Pipeline([("features", features), ("model", model)])
