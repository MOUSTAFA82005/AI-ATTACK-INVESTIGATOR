"""Benign customer text that happens to contain words a naive keyword rule
would flag (select, drop, union, script, order by, 1=1, <3). These are NOT
attacks; they test the false-alarm side. No attack payloads are authored here;
attack rows come only from Elsharawy's generated data."""
import json
import pandas as pd

PHRASES = [
    "select your size at checkout", "please drop off at 5pm", "union station juice bar",
    "I <3 this smoothie", "best script for a smoothie ever", "order by price please",
    "buy one get one, 1=1 deal", "drop me an email when it's back",
    "the selection of juices is great", "and/or more fruit next time",
    "update: still my favorite shop", "a union of great flavors",
    "insert more mango please", "table for two? no, just juice",
    "where do I drop my review?", "script-free checkout, loved it",
    "delete my doubts, this is good", "exec-level service, thanks",
    "char-grilled pineapple? yes!", "having a great day thanks to this",
    "O'Reilly's book recommended you", "can't & won't stop ordering",
    "price = quality here", "5 stars; would buy again!",
    "<3 the packaging", "select menu looked amazing",
    "order #1234 arrived fine", "group order for the office",
    "no sql issues, just good juice", "waitlist was worth it",
]


def rows():
    out = []
    for i, p in enumerate(PHRASES):
        # same phrase in a search and in a feedback comment
        out.append(("GET", f"/rest/products/search?q={p.replace(' ', '%20')}", "", "normal", ""))
        out.append(("POST", "/api/Feedbacks/", json.dumps({"comment": p, "rating": 5}), "normal", ""))
    return pd.DataFrame(out, columns=["method", "path", "body", "label", "attack_type"])


if __name__ == "__main__":
    print(rows().head())
