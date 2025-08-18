import sys, pathlib
sys.path.append(str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from password_strength import evaluate_password

def test_minimal_is_weak():
    res = evaluate_password("abc")
    assert res["label"] in {"Very Weak", "Weak"}

def test_strong_example():
    res = evaluate_password("G00d!EnoughPassword")
    assert res["label"] in {"Strong", "Very Strong"}
