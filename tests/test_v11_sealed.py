"""v11 sealed test code on FAKE files only (V11_DRY). The real sealed folder is never read here."""
import hashlib
import importlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _line(i, method, path):
    return f"[06-01-F{i:06d}]\t{method}\t{path}\tHTTP/1.1\"\t200\t512\n"


@pytest.fixture
def sealed(tmp_path, monkeypatch):
    s = tmp_path / "sealed"
    for d in ("attack", "clean", "raw", "labels", "sid"):
        (s / d).mkdir(parents=True)
    for day in ("2017-06-01", "2017-06-02"):
        (s / "attack" / f"biblio-{day}.att").write_text(
            _line(1, "GET", "/a.php?id=1' union select 1--") * 3 + _line(2, "GET", "/../../etc/passwd"))
        (s / "clean" / f"biblio-{day}.cl").write_text("".join(_line(10 + i, "GET", f"/page/{i}") for i in range(50)))
        (s / "raw" / f"biblio-{day}.raw").write_text(
            _line(1, "GET", "/a.php?id=1' union select 1--") + _line(3, "GET", "/b?q=%27") + _line(4, "GET", "/c?x=<b>"))
        (s / "labels" / f"biblio-{day}.lbl").write_text(
            "[06-01-F000003]\t1\t0\t0\t0\t3\t0\t0\n[06-01-F000004]\t1\t0\t0\t0\t0\t0\t0\n")
        (s / "sid" / f"biblio-{day}.sid").write_text("")
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  ./{p.relative_to(s).as_posix()}"
             for p in sorted(s.rglob("*")) if p.is_file()]
    (tmp_path / "hashes.txt").write_text("\n".join(lines) + "\n")
    monkeypatch.setenv("V11_DRY", str(tmp_path))
    monkeypatch.setenv("V11_CLEAN_N", "30")
    import eval.v11_sealed_test as m
    return importlib.reload(m), tmp_path


def test_convert_and_counts(sealed):
    m, tmp = sealed
    m.convert()
    att = m._load("attack")
    assert len(att) == 2 and att["count"].tolist() == [6, 2]      # dedup over both days
    assert set(att["split"]) == {"sealed"}
    assert len(m._load("clean")) == 30                               # one reservoir over the period
    assert m._load("lvl234")["path"].tolist() == ["/b?q=%27"]
    assert m._load("fp")["path"].tolist() == ["/c?x=<b>"]


def test_hash_mismatch_stops(sealed):
    m, tmp = sealed
    (m.SEALED / "attack" / "biblio-2017-06-01.att").write_text("changed\n")
    with pytest.raises(SystemExit):
        m.convert()
    assert not (m.CONV / "attack.csv").exists()


@pytest.mark.skipif(not (ROOT / "models" / "detector.joblib").exists(), reason="no detector")
def test_run_writes_report(sealed, monkeypatch):
    m, tmp = sealed
    m.convert()
    det = ROOT / "models" / "detector.joblib"
    monkeypatch.setattr(m, "MODELS", {"v10": det, "v11": det})
    res, better = m.run()
    assert better is False                                           # same model cannot be 0.02 better
    text = (m.OUT / "SEALED-RESULTS.md").read_text()
    assert "NOT BETTER" in text and "| payload rules |" in text
    assert res["payload rules"]["macro"] == 1.0                      # both fake attacks are rule-obvious
