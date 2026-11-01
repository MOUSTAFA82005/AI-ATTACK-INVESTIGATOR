"""Benign input that shares characters or words with the newer attack families
(SSRF, XXE, SSTI, NoSQL, Log4Shell, LDAP, XPath): links to public sites, braces,
dollar signs, parentheses, XML-looking text. These are NOT attacks; they test the
false-alarm side of improvement 3. Written before the new model was trained."""
import json

import pandas as pd

PHRASES = [
    "see https://www.example.com/help for details", "my shop is at http://example.org/store",
    "https://maps.google.com/?q=cairo", "ftp://ftp.example.com/pub/catalog.pdf",
    "Dear {customer}, thanks for your order", "price is $5 (or $4 with the coupon)",
    "use code ${SAVE10} at checkout", "costs $10 {incl. tax}",
    "5 stars (really) (no joke)", "great (& cheap) juice", "A* quality, would buy again",
    "rating: 4/5 (good)", "ordered 2 (two) bottles", "user name: admin (not me)",
    "this.is.the.best.juice", "db.json was missing in the app", "x == y? no, x > y",
    "a || b, both fine", "I wrote <xml> in the box by mistake",
    "count me in / count on us", "the text (in the box) was cut",
    "#{1} best seller", "loved it {{really}}", "50% off [[today only]]",
    "e-mail: someone@example.com", "path is /home/user/docs", "item #42 (blue)",
    "call 0100-123-4567", "10.5 kg box", "version 2.0 (beta)",
]


def rows():
    out = []
    for p in PHRASES:
        # same text in a search box and in a feedback comment
        out.append(("GET", f"/rest/products/search?q={p.replace(' ', '%20').replace('#', '%23')}",
                    "", "normal", ""))
        out.append(("POST", "/api/Feedbacks/", json.dumps({"comment": p, "rating": 5}), "normal", ""))
    return pd.DataFrame(out, columns=["method", "path", "body", "label", "attack_type"])


if __name__ == "__main__":
    print(rows().head())
