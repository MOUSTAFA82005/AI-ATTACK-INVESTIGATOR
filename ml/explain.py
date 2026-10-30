"""
explain.py - why the detector called a request an attack.

The detector is XGBoost, and XGBoost can split every prediction into one contribution
per feature (SHAP values, computed exactly for trees with pred_contribs=True; the same
numbers the shap library's TreeExplainer gives, checked in notebook 15). A positive
contribution pushes the request towards "attack", a negative one towards "normal".

reasons() turns the largest positive contributions into short sentences for the
investigation page. It never changes a prediction. Two rules keep the sentences honest:
- only features that are present in the request are named (a feature that is 0 can still
  get a small SHAP value, but "it had no X" is not a reason to call it an attack);
- v_kw_total is the sum of the keyword counts of each family, so its share is handed to
  the families that are present, in proportion to their counts. The size features (how
  many values, how much input) are not named: they do not say what kind of attack it is.
"""
import numpy as np
import xgboost as xgb

# One sentence per value_features() column (ml/features.py).
FEATURE_TEXT = {
    "v_count": "number of values the user sent",
    "v_max_len": "a very long value",
    "v_log_total_len": "a lot of user input in total",
    "v_ctx_quote": "a quote next to SQL syntax",
    "v_ctx_tag": "an HTML tag in a value",
    "v_ctx_attr_break": "a quote that closes an HTML attribute",
    "v_ctx_call": "a function call in a value",
    "v_ctx_shell": "shell characters (` $( | ) in a value",
    "v_chr_backslash": "backslashes in a value",
    "v_chr_brace": "curly braces in a value",
    "v_sql_comment": "an SQL comment (-- or /*)",
    "v_max_special_ratio": "a value made mostly of special characters",
    "v_kw_sql": "SQL keywords",
    "v_kw_xss": "script / event-handler words",
    "v_kw_trav": "path traversal (../) in a value",
    "v_kw_cmd": "an OS command after a separator",
    "v_tautology": "an always-true condition (like OR 1=1)",
    "v_crlf": "line breaks (CR/LF) in the request",
    "p_kw_trav": "path traversal in the URL path",
    "p_bad_chars": "code characters in the URL path",
    "p_kw_xss": "script words in the URL path",
    "p_probe_ext": "a backup or source file extension",
    "p_probe_path": "a hidden or sensitive file path (.git, .env, ...)",
    "double_encoded": "double URL encoding (%25..)",
    "null_byte": "a null byte (%00)",
    "v_kw_total": "many attack keywords in total",
    "scanner_agent": "a known attack tool's user agent",
}


NOT_A_REASON = {"v_count", "v_log_total_len", "v_kw_total"}
KEYWORD_PARTS = ["v_kw_sql", "v_kw_xss", "v_kw_trav", "v_kw_cmd", "p_kw_trav", "p_kw_xss",
                 "p_probe_ext", "p_probe_path"]     # v_kw_total = their sum (ml/features.py)


def contributions(detector, X):
    """SHAP value of every feature for every row of X (the to_frame() table).
    Returns (array rows x features + 1, feature names); the last column is the bias."""
    features, model = detector.named_steps["features"], detector.named_steps["model"]
    names = list(features.get_feature_names_out())
    names = [n.split("__", 1)[1] if "__" in n else n for n in names]
    data = xgb.DMatrix(np.asarray(features.transform(X), dtype=float), feature_names=names)
    values = model.get_booster().predict(data, pred_contribs=True)
    return values, names


def reasons(detector, X, top=3, min_value=0.1):
    """For every row the detector calls an attack: up to `top` sentences for the features
    that pushed it most towards "attack" (SHAP value at least `min_value`, in log-odds).
    Rows it calls normal get an empty list."""
    values, names = contributions(detector, X)
    present = X[names].to_numpy(dtype=float) != 0
    counts = X[KEYWORD_PARTS].to_numpy(dtype=float)
    total, parts = names.index("v_kw_total"), [names.index(n) for n in KEYWORD_PARTS]
    keep = [i for i, n in enumerate(names) if n not in NOT_A_REASON]
    out = []
    for r, row in enumerate(values):
        if row.sum() <= 0:                      # log-odds <= 0: probability <= 0.5, normal
            out.append([])
            continue
        credit = row[:-1].copy()
        if counts[r].sum() > 0:                 # hand v_kw_total's share to its families
            credit[parts] += credit[total] * counts[r] / counts[r].sum()
        order = sorted((i for i in keep if present[r, i]), key=lambda i: -credit[i])[:top]
        out.append([FEATURE_TEXT.get(names[i], names[i]) for i in order if credit[i] >= min_value])
    return out
