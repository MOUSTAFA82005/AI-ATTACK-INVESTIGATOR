import numpy as np

from ml.detector import to_frame
from ml.outliers import unusual_requests


def _log(n_normal, odd_values=()):
    paths = [f"/rest/products/search?q=apple{i % 7}" for i in range(n_normal)]
    paths += [f"/rest/products/search?q={v}" for v in odd_values]
    return to_frame(["GET"] * len(paths), paths, [""] * len(paths))


def test_small_log_is_never_marked():
    assert not unusual_requests(_log(50, ["<script>alert(1)</script>"])).any()


def test_marks_at_most_the_share():
    marked = unusual_requests(_log(1000), share=0.01)
    assert marked.sum() <= 10


def test_odd_value_is_marked_in_a_regular_log():
    marked = unusual_requests(_log(500, ["'><svg/onload=confirm(1)>"]), share=0.01)
    assert marked[-1]


def test_same_answer_every_time():
    X = _log(300, ["a" * 400])
    assert np.array_equal(unusual_requests(X), unusual_requests(X))
