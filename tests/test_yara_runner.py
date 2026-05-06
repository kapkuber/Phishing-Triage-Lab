from pathlib import Path

from triage.mime_walker import walk
from triage.yara_runner import run_rules


def test_yara_compiles_all_rules(synthetic_msg, request):
    fixture_path = Path(request.fspath).parent / "fixtures" / "synthetic_sample.eml"
    raw = fixture_path.read_bytes()
    mime = walk(synthetic_msg)
    atts = [(a.filename or "", a.payload) for a in mime.attachments]
    rep = run_rules(raw, mime.body_text, mime.body_html, atts)

    # All 5 rule files should compile cleanly. If a user breaks one, this test will fail
    # with a clear pointer to which file.
    assert not rep.compile_errors, f"YARA compile errors: {rep.compile_errors}"
    assert rep.rules_compiled == 5


def test_yara_hits_pe_payload_in_synthetic(synthetic_msg, request):
    fixture_path = Path(request.fspath).parent / "fixtures" / "synthetic_sample.eml"
    raw = fixture_path.read_bytes()
    mime = walk(synthetic_msg)
    atts = [(a.filename or "", a.payload) for a in mime.attachments]
    rep = run_rules(raw, mime.body_text, mime.body_html, atts)

    rules_hit = {m.rule for m in rep.matches}
    # The synthetic .eml contains a base64 MZ blob -> base64_pe_executable should fire on raw_eml
    assert "base64_pe_executable" in rules_hit
    # And the lookalike rule should hit on micros0ft.com in the body
    assert "lookalike_domain_strings" in rules_hit
