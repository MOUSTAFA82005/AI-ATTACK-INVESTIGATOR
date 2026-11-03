"""
GraphQL requests: everything goes to one address (POST /graphql) and what the user
typed sits inside the query text, as arguments: pastes(filter: "abc"), paste(id: 7).

For the models a GraphQL request is read like a form: its fields are the argument
names and its values are the argument values (plus the `variables` object). The query
syntax itself ({ } ( ) :) is the client's code, not user input, so it is not a value.
Without this, every ordinary GraphQL request looks like an injection, and logins and
ID sweeps inside the query are invisible.
"""
import json
import re

_ARG = re.compile(r'(?<![\w$])(\w+)\s*:\s*("(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?|true|false|null|\$\w+|\w+)')
_LOOKS_GQL = re.compile(r"^\s*(query|mutation|subscription)?\s*\w*\s*(\([^)]*\))?\s*\{", re.S)


def parse(body):
    """The decoded JSON of a GraphQL request body, or None if the body is not one."""
    b = str(body or "").strip()
    if not b.startswith("{") or '"query"' not in b:
        return None
    try:
        obj = json.loads(b)
    except ValueError:
        return None
    if isinstance(obj, dict) and isinstance(obj.get("query"), str) and _LOOKS_GQL.match(obj["query"]):
        return obj
    return None


def _unquote(v):
    if v.startswith('"') and v.endswith('"'):
        try:
            return json.loads(v)
        except ValueError:
            return v[1:-1]
    return v


_STRING = re.compile(r'"""[\s\S]*?"""|"(?:[^"\\]|\\.)*"')
_GROUP = re.compile(r"\(([^()]*(?:\([^()]*\)[^()]*)*)\)")


def _masked(query):
    """The query with every string literal replaced by "\x00<n>" (so parentheses or quotes
    inside a value cannot break the parsing), and the list of the original literals."""
    found = []

    def keep(m):
        found.append(m.group(0))
        return '"\x00%d"' % (len(found) - 1)
    return _STRING.sub(keep, query), found


def _restore(v, found):
    m = re.fullmatch('"\x00(\\d+)"', v)
    return _unquote(found[int(m.group(1))]) if m else _unquote(v)


def arguments(obj):
    """[(name, value)] of the query's arguments and of the variables object."""
    masked, found = _masked(obj["query"])
    out = []
    # Arguments only live inside ( ... ); field selections ({ id title }) are skipped.
    for group in _GROUP.findall(masked):
        out += [(n, _restore(v, found)) for n, v in _ARG.findall(group) if not v.startswith("$")]
    # A string anywhere else in the query (a directive, a nesting deeper than the groups
    # above) is still something the client sent: never let it go unread.
    used = {v for _, v in out}
    out += [("", s) for s in (_unquote(x) for x in found) if s not in used]
    variables = obj.get("variables")
    if isinstance(variables, dict):
        for n, v in variables.items():
            if isinstance(v, (str, int, float)) and not isinstance(v, bool):
                out.append((n, str(v)))
    return out


def values(body):
    """User values of a GraphQL body (strings and numbers), or None if not GraphQL."""
    obj = parse(body)
    if obj is None:
        return None
    return [str(v) for _, v in arguments(obj) if v not in ("true", "false", "null")]


def field_names(body):
    obj = parse(body)
    return None if obj is None else [n for n, _ in arguments(obj) if n]


def object_ids(body):
    """[(operation.argument, id)] for numeric ID-like arguments: paste(id: 7) -> ("paste.id", "7")."""
    obj = parse(body)
    if obj is None:
        return []
    masked, found = _masked(obj["query"])
    out = []
    for op, group in re.findall(r"(\w+)\s*\(([^()]*)\)", masked):
        for n, v in _ARG.findall(group):
            v = _restore(v, found)
            if re.fullmatch(r"\d+", str(v)) and re.search(r"id$|^id|num|no$", n, re.I):
                out.append((f"{op}.{n}", str(v)))
    return out
