"""v10 dev: why the AIT spiral/insect hydra + nikto recall fell with the v10 session code.
Aggregates only. Runs the AIT hosts under: v10 default, no UA split, no no-size rule,
and UA with digits removed before hashing."""
import re
import sys
import zlib

import eval.final_test as ft
import ml.context_model as cm
import ml.sessions as ses
from eval.v9_ait_eval import load, ML

ORIG = ses.visitor_key


def key_nodigits(df):
    ip = df["ip"].astype(str)
    ua = df["user_agent"].fillna("").astype(str)
    tag = ua.map(lambda u: format(zlib.crc32(re.sub(r"\d+", "", u).encode("utf-8", "replace")), "08x"))
    return ip.where(ua.isin(["", "-"]), ip + "|" + tag)


def run(host, name):
    df = load(host)
    att = df["label"] != "normal"
    for t in ["scan", "bruteforce"]:
        m = df["attack_type"] == t
        ua = df.loc[m, "user_agent"].astype(str)
        if name == "default":
            print(host, t, "rows", int(m.sum()), "distinct UAs", ua.nunique(),
                  "distinct UAs without digits", ua.map(lambda u: re.sub(r"\d+", "", u)).nunique())
    req, _ = ft._pipeline(df.copy())
    out = {t: round(float(req.loc[req["attack_type"] == t, ML].mean()), 3) for t in ["scan", "bruteforce"]}
    norm = req[req["label"] == "normal"]
    out["normal flagged"] = int(norm[ML].sum())
    print(host, name, out, flush=True)


if __name__ == "__main__":
    hosts = sys.argv[1].split(",") if len(sys.argv) > 1 else ["spiral", "insect", "onion"]
    for host in hosts:
        ses.SPLIT_BY_AGENT, cm.NO_SIZE_SHARE, ses.visitor_key = True, 0.9, ORIG
        run(host, "default")
        ses.SPLIT_BY_AGENT = False
        run(host, "no UA split")
        ses.SPLIT_BY_AGENT, cm.NO_SIZE_SHARE = True, 2.0
        run(host, "no no-size rule")
        cm.NO_SIZE_SHARE, ses.visitor_key = 0.9, key_nodigits
        run(host, "UA without digits")
