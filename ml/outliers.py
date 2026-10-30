"""
outliers.py - "unusual request" marks from an Isolation Forest fitted on the uploaded log itself.

Isolation Forest learns what the requests of THIS log usually look like (no labels) and
marks the few that are easiest to tell apart from the rest. It is a second opinion next
to the detector, meant for attack kinds nobody trained on:

- it never changes the detector's decision: an unusual request is shown as
  "unusual, review it", not counted as an attack;
- it is fitted on each log, because fitted on public traffic it marked about half of
  the normal requests of our lab sites (notebook 13);
- it uses the same site-independent value_features as the detector, so requests that
  carry no user values are never unusual.

Dev runs (notebook 13): with the top 1% marked, 0 normal requests were marked, and every
marked request was one the detector had already flagged. Whether it finds anything the
detector misses is measured once, on run6 and the real-tool logs.
"""
import numpy as np
from sklearn.ensemble import IsolationForest

UNUSUAL_SHARE = 0.01     # mark at most this share of a log
MIN_REQUESTS = 200       # smaller logs have too little "usual" traffic to compare with


def unusual_requests(X, share=UNUSUAL_SHARE, min_requests=MIN_REQUESTS):
    """X: the to_frame() table of a log. Returns a bool array, True = unusual request."""
    hand = X[[c for c in X.columns if c != "text"]].astype(float)
    if len(hand) < min_requests or hand.drop_duplicates().shape[0] < 2:
        return np.zeros(len(hand), dtype=bool)
    iso = IsolationForest(n_estimators=200, contamination=share, random_state=0, n_jobs=2)
    return iso.fit(hand).predict(hand) == -1
