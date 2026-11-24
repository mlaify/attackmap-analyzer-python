"""SDK 1.0 conformance (mlaify/AttackMap#254): attackmap.sdk.testing.assert_conforms."""

from pathlib import Path

from attackmap.sdk.testing import assert_conforms

from attackmap_analyzer_python import PythonAnalyzer


def _has_signals(result) -> None:
    assert any(isinstance(v, list) and v for v in result.__dict__.values()), "the analyzer emitted nothing"


SAMPLE = {'app.py': "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/users/<int:uid>')\ndef user(uid):\n    return str(uid)\n"}


def test_conforms_to_the_sdk(tmp_path: Path) -> None:
    for rel, text in SAMPLE.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text, encoding="utf-8")
    _has_signals(assert_conforms(PythonAnalyzer(), tmp_path))
