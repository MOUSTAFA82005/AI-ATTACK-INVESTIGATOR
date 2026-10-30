import numpy as np
import pytest

from ml.detector import build_pipeline, to_frame
from ml.explain import FEATURE_TEXT, contributions, reasons


@pytest.fixture(scope="module")
def detector():
    """A small detector trained here, so the test needs no model file."""
    normal = ([f"/search?q=apple{i}" for i in range(40)] + [f"/item?id={i}" for i in range(40)]
              + [f"/search?q=green apples and pears number {i}" for i in range(40)])
    attack = ([f"/search?q=a' or 1=1--{i}" for i in range(20)]
              + [f"/search?q=<script>alert({i})</script>" for i in range(20)])
    paths = normal + attack
    X = to_frame(["GET"] * len(paths), paths, [""] * len(paths))
    y = [0] * len(normal) + [1] * len(attack)
    hand = [c for c in X.columns if c != "text"]
    return build_pipeline(hand, n_jobs=1).fit(X, y)


def test_every_feature_has_a_sentence(detector):
    _, names = contributions(detector, to_frame(["GET"], ["/a?b=c"], [""]))
    assert set(names) == set(FEATURE_TEXT)


def test_contributions_add_up_to_the_probability(detector):
    X = to_frame(["GET", "GET"], ["/search?q=pear", "/search?q=x' or 1=1--"], ["", ""])
    values, _ = contributions(detector, X)
    proba = 1 / (1 + np.exp(-values.sum(axis=1)))
    assert np.allclose(proba, detector.predict_proba(X)[:, 1], atol=1e-4)


def test_normal_request_gets_no_reason(detector):
    assert reasons(detector, to_frame(["GET"], ["/search?q=pear"], [""])) == [[]]


def test_reasons_name_only_what_is_in_the_request(detector):
    (sql,) = reasons(detector, to_frame(["GET"], ["/search?q=x' or 1=1--"], [""]))
    assert sql and not any("script" in r for r in sql)
    (xss,) = reasons(detector, to_frame(["GET"], ["/search?q=<script>alert(1)</script>"], [""]))
    assert xss and not any("SQL" in r for r in xss)
