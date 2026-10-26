"""
Join the generator's per-request labels (requests.csv) to the Nginx log lines.

Each fake IP sends its requests one after another, so inside one IP the k-th
log line with a given "METHOD path" is the k-th request of that kind in
requests.csv. Query strings are ignored for the match, so this also works
with labels written before the generator logged full paths.

    python -m eval.match_labels data/raw/x.log data/labels/requests.csv out.csv
"""
import sys

import pandas as pd

from backend.app.log_parser import parse_log


def match(log_path, labels_path):
    """Return (labelled DataFrame, report dict)."""
    rows, _ = parse_log(open(log_path, encoding="utf-8", errors="replace").read())
    log = pd.DataFrame(rows)
    log["t"] = pd.to_datetime(log["time"], format="%d/%b/%Y:%H:%M:%S %z")
    lab = pd.read_csv(labels_path, keep_default_na=False)
    lab["t"] = pd.to_datetime(lab["time"])
    log = log[log["t"] >= lab["t"].min() - pd.Timedelta(seconds=2)].copy()   # drop older runs
    log["key"] = log["method"] + " " + log["path"].str.split("?").str[0]
    lab["key"] = lab["method"] + " " + lab["path"].str.split("?").str[0]

    out, extra_log, missing_lab = [], 0, 0
    for ip, L in log.groupby("ip", sort=False):
        R = lab[lab["ip"] == ip].reset_index(drop=True)
        j = 0
        for _, row in L.iterrows():
            if j < len(R) and row["key"] == R.loc[j, "key"]:
                out.append({**row.to_dict(), "label": R.loc[j, "label"],
                            "attack_type": R.loc[j, "attack_type"]})
                j += 1
            else:
                extra_log += 1
        missing_lab += len(R) - j
    m = pd.DataFrame(out).drop(columns=["t", "key"])
    report = {"log_lines": len(log), "labels": len(lab), "matched": len(m),
              "unmatched_log_lines": extra_log, "unmatched_labels": missing_lab}
    return m, report


if __name__ == "__main__":
    m, report = match(sys.argv[1], sys.argv[2])
    print(report)
    m.to_csv(sys.argv[3], index=False)
