"""
detector.py - the attack-detection model (normal vs attack) for one request.

Shared by the training script and the backend, so both turn a request into
features in exactly the same way.

Model: XGBoost on value_features() from features.py. These features look only
at what the user typed (parameter and body values, plus traversal/probe marks
in the path), so the model is not tied to one site. See
notebooks/04_site_independent_detector.ipynb for why: the old whole-request
features flagged 96% of normal Juice Shop traffic; these flag 0%.
"""
import re
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier

from ml.features import user_values, value_features

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "models" / "detector.joblib"

# Features that only fire when a request carries something suspicious.
_SIGNAL_PREFIXES = ("v_ctx_", "v_chr_", "v_kw", "p_", "v_sql", "v_taut", "v_crlf", "double", "null")


def _shape(path, body):
    """User values only, lowercase, digits -> 0 (for the optional TF-IDF part)."""
    return re.sub(r"\d", "0", "\n".join(user_values(path, body)).lower())


def to_frame(methods, paths, bodies):
    """Turn lists of (method, path, body) into the table the model expects."""
    methods = [str(m or "GET").upper() for m in methods]
    paths = [str(p or "") for p in paths]
    bodies = [str(b or "") for b in bodies]
    text = [_shape(p, b) for p, b in zip(paths, bodies)]
    hand = pd.DataFrame([value_features(m, p, b) for m, p, b in zip(methods, paths, bodies)])
    return pd.concat([pd.DataFrame({"text": text}), hand], axis=1)


def signal_columns(X):
    return [c for c in X.columns if c.startswith(_SIGNAL_PREFIXES)]


def has_payload(X):
    """True for requests that carry at least one attack signal."""
    return X[signal_columns(X)].sum(axis=1) > 0


# Files a site may really offer for download. A request for one is a probe when a
# scanner guesses it, but not when the site serves it to an ordinary visitor.
DOWNLOAD_EXT = (".tar", ".gz", ".tgz", ".zip", ".conf", ".ini", ".java")
_FILE_SIGNALS = ["p_probe_ext", "p_probe_path", "v_kw_total"]   # v_kw_total counts the first two


def served_files(df, X, pred):
    """Alarms that are only a download-like file name (.conf, .tar.gz, ...) that the site
    served (2xx/3xx, or 416 = range of an existing file) to an IP with no other alarm.

    Those are visitors downloading a real file, not scanners: a scanner guesses many
    names and gets them refused, or also sends payloads. The caller sets pred to 0 for
    these and keeps them as "unusual, review it". df needs ip, path, status."""
    pred = np.asarray(pred).astype(bool)
    path = df["path"].astype(str).str.split("?").str[0].str.lower().str.rstrip("/")
    file_only = X[signal_columns(X)].drop(columns=_FILE_SIGNALS).sum(axis=1).values == 0
    status = pd.to_numeric(df["status"], errors="coerce").fillna(0).values
    served = ((status >= 200) & (status < 400)) | (status == 416)
    cand = pred & file_only & served & path.map(lambda p: p.endswith(DOWNLOAD_EXT)).values \
        & (X["p_probe_path"].values == 0)
    other_alarm = pd.Series(pred & ~cand, index=df.index).groupby(df["ip"].values).transform("any").values
    return cand & ~other_alarm


def build_pipeline(hand_cols, pos_weight=1.0, n_jobs=2, use_tfidf=False):
    """use_tfidf=True also adds character n-grams of the user values."""
    parts = [("hand", "passthrough", hand_cols)]
    if use_tfidf:
        parts.insert(0, ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(2, 4), min_df=2,
                                                  max_features=2_000, sublinear_tf=True,
                                                  dtype=np.float32), "text"))
    features = ColumnTransformer(parts)
    model = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1, tree_method="hist",
                          max_bin=32, scale_pos_weight=pos_weight, n_jobs=n_jobs,
                          random_state=42, eval_metric="logloss")
    return Pipeline([("features", features), ("model", model)])
