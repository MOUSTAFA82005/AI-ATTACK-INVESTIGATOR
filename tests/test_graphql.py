import json

from ml import graphql
from ml.context_model import _object_id
from ml.features import user_values


def _body(query, variables=None):
    obj = {"query": query}
    if variables is not None:
        obj["variables"] = variables
    return json.dumps(obj)


def test_parse_only_graphql_bodies():
    assert graphql.parse(_body("query { pastes { id } }")) is not None
    assert graphql.parse('{"username": "a", "password": "b"}') is None
    assert graphql.parse("q=1") is None
    assert graphql.parse('{"query": "not graphql at all"}') is None


def test_values_are_arguments_not_syntax():
    b = _body('query { pastes(filter: "hello", limit: 5) { id title } }')
    assert graphql.values(b) == ["hello", "5"]
    assert graphql.field_names(b) == ["filter", "limit"]


def test_variables_are_values():
    b = _body("mutation Login($u: String) { login(username: $u) { accessToken } }",
              {"u": "admin", "p": "x"})
    assert sorted(graphql.values(b)) == ["admin", "x"]


def test_injection_in_argument_is_kept():
    b = _body("query { pastes(filter: \"' OR 1=1 --\") { id } }")
    assert "' OR 1=1 --" in graphql.values(b)


def test_object_ids():
    assert graphql.object_ids(_body("query { paste(id: 7) { title } }")) == [("paste.id", "7")]
    assert graphql.object_ids(_body('query { pastes(filter: "7") { id } }')) == []


def test_user_values_reads_graphql_body():
    b = _body('query { pastes(filter: "hello") { id } }')
    assert user_values("/graphql", b) == ["hello"] or "hello" in user_values("/graphql", b)


def test_named_ids_last_segment_only():
    assert _object_id("/books/v1/bookTitle42") == ("/books/v1/bookTitle{id}", "42")
    assert _object_id("/api/v1/") == (None, None)
    assert _object_id("/static/logo2.png") == (None, None)
    res, rid = _object_id("/graphql", _body("query { paste(id: 9) { title } }"))
    assert rid == "9"


def test_parentheses_inside_a_string_do_not_hide_the_value():
    payload = "a)/**/AND/**/(SELECT(CASE/**/WHEN/**/(1=2)/**/THEN/**/1/**/END))--"
    b = _body('query { pastes(filter: %s) { id title } }' % json.dumps(payload))
    assert payload in graphql.values(b)
    assert graphql.field_names(b) == ["filter"]


def test_strings_outside_argument_groups_are_still_values():
    b = _body('query { a(x: 1) { b(y: 2) { c(z: "<script>(1)") { id } } } }')
    assert "<script>(1)" in graphql.values(b)


def test_ids_with_strings_next_to_them():
    b = _body('query { paste(title: "x)(", id: 12) { id } }')
    assert ("paste.id", "12") in graphql.object_ids(b)
