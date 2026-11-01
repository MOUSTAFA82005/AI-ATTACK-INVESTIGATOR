"""
new_families.py - turn the public payloads of the new attack families into requests.

data/raw/new_families.csv (built by ml/build_new_families.py) holds bare payloads.
To train and test on whole requests, each payload is put inside a NORMAL CSIC 2010
request, the same way HttpParams values sit in a parameter:

* most payloads replace the value of one parameter (query or form body), URL-encoded;
* NoSQL payloads written as parameters ("user[$ne]=1&pass[$ne]=1") become the query string;
* XXE documents and NoSQL JSON objects become the POST body.

Each payload is used in COPIES different requests (different page, method and
parameter), so the model learns the payload, not the request around it. For training,
families with few public payloads (LDAP has 8) get more copies, up to MIN_ROWS
requests per family, so the model does not ignore them.
"""
import base64
import math
import random
from urllib.parse import parse_qsl, quote

import pandas as pd

from ml.detector import ROOT, to_frame

NEW_FAMILIES_CSV = ROOT / "data" / "raw" / "new_families.csv"
COPIES = 4
MIN_ROWS = 200      # training rows per family at least (more copies of the same payloads)
MAX_COPIES = 25


def _with_value(path, body, payload, rng):
    """Replace the value of one parameter (in the query, or else in the form body)."""
    base, _, query = path.partition("?")
    where = "query" if query else "body"
    pairs = parse_qsl(query if query else body, keep_blank_values=True)
    if not pairs:
        pairs, where = [("q", "")], "query"
    i = rng.randrange(len(pairs))
    pairs[i] = (pairs[i][0], payload)
    text = "&".join(f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in pairs)
    return (base + "?" + text, body) if where == "query" else (path, text)


def to_requests(payloads, families, normals, copies=COPIES, seed=0):
    """Lists of (method, path, body, family): every payload inside `copies` normal requests.
    copies can be a number or {family: number}."""
    rng = random.Random(seed)
    per_family = copies if isinstance(copies, dict) else {}
    rows = normals[["Method", "path", "body"]].values.tolist()
    out = []
    for payload, family in zip(payloads, families):
        is_doc = payload.lstrip().startswith(("<", "{"))
        is_params = family == "nosql" and "[$" in payload and "=" in payload
        for c in range(per_family.get(family, copies if isinstance(copies, int) else COPIES)):
            method, path, body = rng.choice(rows)
            if family == "xxe" and c % 2 == 0 or family == "nosql" and is_doc and c % 2 == 0:
                out.append(("POST", path.split("?")[0], payload, family))       # the document is the body
            elif is_params:
                out.append(("GET", path.split("?")[0] + "?" + payload.replace(" ", "%20"), "", family))
            else:
                p, b = _with_value(path, body, payload, rng)
                out.append((method, p, b, family))
    return out


def read_payloads():
    """data/raw/new_families.csv with the payloads decoded (stored base64, see ml/build_new_families.py)."""
    df = pd.read_csv(NEW_FAMILIES_CSV, keep_default_na=False)
    df["payload"] = [base64.b64decode(v).decode() for v in df.pop("payload_b64")]
    return df


def load(split, normals=None, copies=None, seed=0):
    """(X, y, family, requests) for one split ("train" or "heldout"); y is 1 for every row.
    By default "train" is balanced (see MIN_ROWS) and "heldout" uses COPIES per payload."""
    df = read_payloads()
    df = df[df["split"] == split]
    if copies is None:
        n = df["family"].value_counts()
        copies = {f: min(MAX_COPIES, max(COPIES, math.ceil(MIN_ROWS / k))) for f, k in n.items()} \
            if split == "train" else COPIES
    if normals is None:
        csic = pd.read_csv(ROOT / "data" / "processed" / "csic_clean.csv", keep_default_na=False)
        normals = csic[csic["label"] == 0]
    reqs = to_requests(df["payload"], df["family"], normals, copies, seed)
    X = to_frame([r[0] for r in reqs], [r[1] for r in reqs], [r[2] for r in reqs])
    fam = pd.Series([r[3] for r in reqs])
    return X, pd.Series(1, index=X.index), fam, reqs
