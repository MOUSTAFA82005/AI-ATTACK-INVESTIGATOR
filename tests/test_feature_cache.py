"""value_features is cached for speed; the cache must never change an answer."""
from ml.features import _value_features, value_features


def test_cached_result_is_a_fresh_copy():
    a = value_features("GET", "/a?id=1' or 1=1--", "")
    a["v_count"] = -1
    assert value_features("GET", "/a?id=1' or 1=1--", "")["v_count"] != -1


def test_none_and_empty_give_the_same_features():
    _value_features.cache_clear()
    assert value_features("POST", "/login", None) == value_features("POST", "/login", "")
    assert value_features("GET", None, None) == value_features("GET", "", "")
