from ml.next_step import NextStepModel, merge_steps


def test_merge_steps_drops_noise_and_repeats():
    acts = ["scan", "scan", "scan", "sqli", "xss", "sqli", "sqli", "xss", "xss"]
    assert merge_steps(acts) == ["scan", "sqli", "xss"]
    assert merge_steps(["scan", "sqli"], min_run=1) == ["scan", "sqli"]


def test_markov_learns_the_common_transition_and_never_repeats():
    model = NextStepModel.fit([["scan", "sqli"]] * 9 + [["scan", "xss"]])
    first, prob = model.predict("scan", k=1)[0]
    assert first == "sqli" and prob > 0.5
    assert model.transitions.loc["scan", "scan"] == 0
    assert abs(model.transitions.loc["xss"].sum() - 1) < 1e-9
    assert model.predict("unknown") == []
