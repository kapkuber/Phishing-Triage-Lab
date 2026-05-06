from triage.auth_validator import parse_auth_results


def test_parse_spf_dkim_dmarc_verdicts(synthetic_msg):
    rep = parse_auth_results(synthetic_msg)
    assert rep.spf == "fail"
    assert rep.dkim == "fail"
    assert rep.dmarc == "fail"
    assert rep.raw_results, "raw header text should be captured"
