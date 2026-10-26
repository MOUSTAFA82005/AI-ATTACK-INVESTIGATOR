"""
Rules-only baseline: call a request an attack if any keyword pattern from
ml/features.py matches what the user typed (or the path). No learning.

Every results table compares the ML models against this, so we can show what
the ML adds on top of hand-written rules.
"""
import numpy as np

from ml.features import _COMPILED, user_values

_PATTERNS = [p for family in _COMPILED.values() for p in family]


def rule_predict(methods, paths, bodies):
    out = []
    for path, body in zip(paths, bodies):
        text = (" ".join(user_values(path, body)) + " " + str(path or "")).lower()
        out.append(int(any(p.search(text) for p in _PATTERNS)))
    return np.array(out)
