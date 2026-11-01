"""A query part with no "=" is still something the user typed, so it must be read as a value."""
from ml.features import user_values


def test_bare_query_is_a_value():
    assert user_values("/page.x?%3Cscript%3Ealert(1)%3C/script%3E") == ["<script>alert(1)</script>"]


def test_bare_part_next_to_named_parameters():
    assert sorted(user_values("/a.php?debug&id=7")) == ["7", "debug"]


def test_named_parameters_unchanged():
    assert user_values("/search?q=green+tea&page=2") == ["green tea", "2"]
    assert user_values("/search?q=") == []
