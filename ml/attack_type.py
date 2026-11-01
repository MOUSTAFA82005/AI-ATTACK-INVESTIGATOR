"""
attack_type.py - which kind of attack a request carries.

The detector only says attack / normal. For an investigation we also want the
kind: sqli, xss, traversal, cmdi, the newer families (ssrf, xxe, ssti, nosql,
log4shell, ldap, xpath), or scan (a probe for a hidden file).

Two parts:
1) Rules: for each attack family, count how many of its patterns (the same
   regular expressions as in features.py) match the user values and the path.
   The family with the most matching patterns wins. Easy to explain.
2) A small model for the cases the rules cannot decide (no pattern matches,
   or two families tie). It is trained on the HttpParams attack types and the
   public payloads of the newer families (ml/new_families.py), not on our
   generator, so it does not learn the generator.
   Train it with: python -m ml.train_attack_type
   If models/attack_type.joblib is missing, ties use a fixed order instead.

Domain rules, applied before the counts: a Log4j lookup (${jndi:ldap://...}) is
log4shell even though it also holds a URL; an XML DOCTYPE/ENTITY is xxe even though
it also names a file or URL; a template tag that runs a command is ssti, not cmdi.
And in a tie, cmdi beats traversal ("; cat /etc/passwd": a shell command reads the file).

See notebooks/08_attack_type.ipynb.
"""
import joblib

from ml.detector import ROOT, to_frame
from ml.features import _COMPILED, _TAUTOLOGY, _dec, new_family_hits, user_values, value_features

OLD_TYPES = ["sqli", "xss", "traversal", "cmdi"]
NEW_TYPES = ["ssrf", "xxe", "ssti", "nosql", "log4shell", "ldap", "xpath"]
TYPES = OLD_TYPES + NEW_TYPES
TYPE_MODEL_PATH = ROOT / "models" / "attack_type.joblib"
_FAMILY = {"sql": "sqli", "xss": "xss", "trav": "traversal", "cmd": "cmdi"}
_NEW_FAMILY = {"log4j": "log4shell"}               # feature name -> type name
_ALWAYS = ["log4shell", "xxe"]                      # if present, the type (see the note above)
_TIE_ORDER = ["log4shell", "xxe", "ssti", "nosql", "ldap", "xpath", "ssrf",
              "cmdi", "xss", "traversal", "sqli"]     # used only without the model


def rule_scores(method, path, body=""):
    """Number of matching patterns per attack family, plus probe marks for scan."""
    url_path = _dec(str(path or "").split("?", 1)[0]).lower()
    text = "\n".join(user_values(path, body)).lower()
    s = {}
    for fam, pats in _COMPILED.items():
        hits = sum(bool(p.search(text)) for p in pats)
        if fam in ("trav", "xss"):                      # these can also sit in the path
            hits += sum(bool(p.search(url_path)) for p in pats)
        s[_FAMILY[fam]] = hits
    s["sqli"] += int(bool(_TAUTOLOGY.search(text)))
    for fam, hits in new_family_hits(path, body).items():
        s[_NEW_FAMILY.get(fam, fam)] = hits
    f = value_features(method, path, body)
    s["scan"] = f["p_probe_ext"] + f["p_probe_path"]
    return s


def _pick(scores, proba):
    for t in _ALWAYS:
        if scores[t]:
            return t
    if scores["ssti"] and scores["cmdi"]:
        scores = {**scores, "cmdi": 0}
    top = max(scores[t] for t in TYPES)
    if top == 0:
        if scores["scan"]:
            return "scan"
        cands = TYPES
    else:
        cands = [t for t in TYPES if scores[t] == top]
        if len(cands) == 1:
            return cands[0]
        if "cmdi" in cands and "traversal" in cands:
            return "cmdi"
    if proba is None:
        return "other" if top == 0 else min(cands, key=_TIE_ORDER.index)
    return max(cands, key=lambda t: proba[TYPES.index(t)])


def load_type_model():
    return joblib.load(TYPE_MODEL_PATH) if TYPE_MODEL_PATH.exists() else None


def attack_types(methods, paths, bodies, model=None):
    """One type per request. Call it only for requests flagged as attacks."""
    methods, paths, bodies = list(methods), list(paths), list(bodies)
    if not paths:
        return []
    probas = [None] * len(paths)
    if model is not None:
        X = to_frame(methods, paths, bodies).drop(columns="text")
        probas = model.predict_proba(X)
    return [_pick(rule_scores(m, p, b), pr) for m, p, b, pr in zip(methods, paths, bodies, probas)]
