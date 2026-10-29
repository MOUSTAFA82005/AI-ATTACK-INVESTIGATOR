"""
next_step.py - what an attacker is likely to do next (Markov chain).

1) From the requests of one session, read the attacker's steps in order:
   each flagged request is one activity (its attack type if the detector
   caught a payload, else the session behaviour: scan, enum, bruteforce).
   Runs shorter than MIN_RUN requests are dropped as noise (one stray
   request typed differently), then repeats are merged:
       scan scan scan enum enum sqli sqli  ->  scan > enum > sqli
2) A first-order Markov chain: P(next step | current step), counted from
   attacker step sequences, with add-one smoothing so no step is impossible.
3) For a session, the prediction is the most likely next steps after its
   last step, with their probabilities.

The chain is trained on our generated campaigns (python -m ml.train_next_step),
so it learns the scenarios we wrote, not real attackers. That is said in the report.
See notebooks/11_next_step.ipynb.
"""
import itertools
import json

import pandas as pd

from ml.detector import ROOT

STEPS = ["scan", "enum", "bruteforce", "sqli", "xss", "traversal", "cmdi"]
MIN_RUN = 2
NEXT_STEP_PATH = ROOT / "models" / "next_step.json"
_BEHAVIOUR_STEP = {"scan": "scan", "enumeration": "enum", "bruteforce": "bruteforce"}


def merge_steps(activities, min_run=MIN_RUN):
    """['scan','scan','sqli','xss','sqli','sqli'] -> ['scan', 'sqli'] (with min_run=2)."""
    runs = [(k, len(list(g))) for k, g in itertools.groupby(a for a in activities if a in STEPS)]
    return [k for k, _ in itertools.groupby(k for k, n in runs if n >= min_run)]


def session_steps(req):
    """
    req: the request DataFrame of the pipeline (analyze_sessions output plus `type_pred`
    for requests the detector flagged). Returns {session: [steps in order]} for every
    session with at least one step.
    """
    flagged = req[(req["pred"] == 1) | (req["session_attack"] == 1)].sort_values(["session", "timestamp"],
                                                                                  kind="stable")
    act = [t if p == 1 else _BEHAVIOUR_STEP.get(b, "")
           for p, b, t in zip(flagged["pred"], flagged["behaviour"], flagged["type_pred"])]
    flagged = flagged.assign(_act=act)
    out = {}
    for session, g in flagged.groupby("session", sort=False):
        steps = merge_steps(g["_act"])
        if steps:
            out[session] = steps
    return out


class NextStepModel:
    def __init__(self, transitions):
        self.transitions = transitions          # DataFrame: rows = current step, columns = next step

    @classmethod
    def fit(cls, sequences, alpha=1.0):
        counts = pd.DataFrame(alpha, index=STEPS, columns=STEPS, dtype=float)
        for seq in sequences:
            for a, b in zip(seq, seq[1:]):
                if a in STEPS and b in STEPS and a != b:
                    counts.loc[a, b] += 1
        for s in STEPS:                         # merged sequences never repeat a step
            counts.loc[s, s] = 0
        return cls(counts.div(counts.sum(axis=1), axis=0))

    def predict(self, current, k=3):
        """[(step, probability), ...] for the k most likely next steps."""
        if current not in STEPS:
            return []
        row = self.transitions.loc[current].sort_values(ascending=False)
        return [(s, round(float(p), 3)) for s, p in row.head(k).items()]

    def top_k_accuracy(self, sequences, k=1):
        hits = n = 0
        for seq in sequences:
            for a, b in zip(seq, seq[1:]):
                n += 1
                hits += b in [s for s, _ in self.predict(a, k)]
        return hits / n if n else float("nan"), n

    def save(self, path=NEXT_STEP_PATH):
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps({"steps": STEPS, "transitions": self.transitions.round(6).to_dict("index")},
                                   indent=1))

    @classmethod
    def load(cls, path=NEXT_STEP_PATH):
        if not path.exists():
            return None
        data = json.loads(path.read_text())
        return cls(pd.DataFrame(data["transitions"]).T.loc[STEPS, STEPS])


def add_next_steps(req, sessions, model, k=3):
    """Per session: the steps seen (`steps`) and the likely next ones (`next_steps`)."""
    steps = session_steps(req)
    sessions = sessions.copy()
    sessions["steps"] = sessions["session"].map(steps).apply(lambda s: s if isinstance(s, list) else [])
    sessions["next_steps"] = sessions["steps"].apply(
        lambda s: model.predict(s[-1], k) if (model is not None and s) else [])
    return sessions
