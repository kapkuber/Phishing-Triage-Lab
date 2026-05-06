from triage.header_parser import parse_headers


def test_received_chain_ordered_origin_first(synthetic_msg):
    rep = parse_headers(synthetic_msg)
    assert len(rep.received_chain) == 3
    # Origin (index 0) is the earliest hop, which corresponds to the bottom-most Received header.
    assert rep.received_chain[0].ip == "185.220.101.7"
    assert rep.received_chain[-1].ip == "10.0.0.5"


def test_originating_ip_is_first_public(synthetic_msg):
    rep = parse_headers(synthetic_msg)
    assert rep.originating_ip == "185.220.101.7"


def test_private_ip_classified(synthetic_msg):
    rep = parse_headers(synthetic_msg)
    last_hop = rep.received_chain[-1]
    assert last_hop.is_private is True


def test_address_divergence_flagged(synthetic_msg):
    rep = parse_headers(synthetic_msg)
    # Reply-To and Return-Path both diverge from From
    assert any("Reply-To" in f for f in rep.divergence_flags)
    assert any("Return-Path" in f for f in rep.divergence_flags)


def test_from_parsing(synthetic_msg):
    rep = parse_headers(synthetic_msg)
    assert rep.from_addr == "ceo@micros0ft.com"
    assert "CEO" in rep.from_display
    assert rep.from_domain == "micros0ft.com"
