"""
Train the next-step model (Markov chain) on the step order of our generated
campaigns and save it to models/next_step.json. Run from the repo root:

    python -m ml.train_next_step

Needs the session label files of a campaign run (development data, default
camp7: data/labels/sessions_camp7.csv and sessions_dvwa_camp7.csv), whose
`steps` column holds each campaign's order, e.g. scan>enum>sqli.
"""
import sys

import pandas as pd

from ml.detector import ROOT
from ml.next_step import NextStepModel, merge_steps

LABELS = ROOT / "data" / "labels"


def campaign_sequences(tag="camp7"):
    seqs = []
    for f in sorted(LABELS.glob(f"sessions*_{tag}.csv")):
        df = pd.read_csv(f, keep_default_na=False)
        steps = df.loc[df["attack_type"] == "campaign", "steps"]
        seqs += [merge_steps(s.split(">"), min_run=1) for s in steps]
    return seqs


def main(tag="camp7"):
    seqs = campaign_sequences(tag)
    if not seqs:
        raise SystemExit(f"no campaigns found in {LABELS}/sessions*_{tag}.csv")
    model = NextStepModel.fit(seqs)
    model.save()
    print(f"trained on {len(seqs)} campaigns ({sum(len(s) - 1 for s in seqs)} steps), saved to models/next_step.json")


if __name__ == "__main__":
    main(*sys.argv[1:])
