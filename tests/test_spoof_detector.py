from triage.spoof_detector import (
    detect_display_name_brand_spoof,
    detect_exec_impersonation,
    detect_lookalike,
    detect_lookalike_in_urls,
)


def test_exec_impersonation_flagged_when_domain_unknown():
    findings = detect_exec_impersonation("Jane Doe, CEO", "micros0ft.com", known_domains=["legitcorp.com"])
    assert len(findings) == 1
    assert findings[0].kind == "exec_impersonation"


def test_exec_impersonation_skipped_when_domain_allowlisted():
    findings = detect_exec_impersonation("Jane Doe, CEO", "legitcorp.com", known_domains=["legitcorp.com"])
    assert findings == []


def test_exec_impersonation_skipped_without_title():
    findings = detect_exec_impersonation("Jane Doe", "evil.com", known_domains=[])
    assert findings == []


def test_lookalike_homoglyph():
    # 'micros0ft.com' substitutes 0 for o
    findings = detect_lookalike("micros0ft.com", brands=["microsoft.com"])
    assert any("Homoglyph" in f.detail for f in findings)


def test_lookalike_levenshtein():
    # 'paypall.com' is one edit away from 'paypal.com'
    findings = detect_lookalike("paypall.com", brands=["paypal.com"])
    assert any("Levenshtein" in f.detail for f in findings)


def test_lookalike_tld_swap():
    findings = detect_lookalike("microsoft.tk", brands=["microsoft.com"])
    assert any("TLD swap" in f.detail for f in findings)


def test_no_lookalike_for_real_domain():
    findings = detect_lookalike("microsoft.com", brands=["microsoft.com"])
    assert findings == []


def test_lookalike_in_url_path_catches_office356():
    # The exact case observed in sample-3026: a legit cloud bucket hosting
    # phishing under a brand-typosquat path segment.
    urls = ["https://storage.googleapis.com/office356/work.html#xyz"]
    findings = detect_lookalike_in_urls(urls, brands=["office365.com"])
    assert findings, "should catch office356 vs office365 in URL path"
    f = findings[0]
    assert f.kind == "lookalike_in_url"
    assert f.location == "path"
    assert "office356" in f.domain
    assert f.target_brand == "office365.com"
    assert f.source_url == urls[0]


def test_lookalike_in_url_subdomain():
    urls = ["https://login.micros0ft.com.attacker.tk/auth"]
    findings = detect_lookalike_in_urls(urls, brands=["microsoft.com"])
    assert any(f.location == "subdomain" and "micros0ft" in f.domain for f in findings)


def test_lookalike_in_url_skips_legit_brand_domain():
    urls = ["https://login.microsoftonline.com/oauth2/v2.0/authorize"]
    findings = detect_lookalike_in_urls(urls, brands=["microsoft.com"])
    # 'microsoftonline' is too far from 'microsoft' (Levenshtein 6) and not a homoglyph.
    # 'login' / 'oauth2' / 'authorize' shouldn't trip anything either.
    assert all(f.target_brand != "microsoft.com" or f.location != "host" for f in findings)


def test_display_name_brand_spoof_docusign_from_gmail():
    # The exact case from sample-1182.
    findings = detect_display_name_brand_spoof("DocuSign", "gmail.com", brands=["docusign.com"])
    assert findings and findings[0].target_brand == "docusign.com"


def test_display_name_brand_spoof_two_word_brand():
    # The exact case from sample-6467: "Omaha Steaks" displayed; from-domain not omahasteaks.com.
    findings = detect_display_name_brand_spoof(
        "Omaha Steaks", "omahasteaksgry.com", brands=["omahasteaks.com"]
    )
    assert findings and findings[0].target_brand == "omahasteaks.com"


def test_display_name_brand_spoof_skipped_when_legit():
    findings = detect_display_name_brand_spoof("DocuSign", "docusign.com", brands=["docusign.com"])
    assert findings == []


def test_display_name_brand_spoof_skipped_for_short_brand():
    # 'aws' is on the brand list but only 3 chars — too short, FP risk.
    findings = detect_display_name_brand_spoof("aws", "evil.com", brands=["aws.amazon.com"])
    assert findings == []  # because tldextract picks 'amazon' as the label, which IS >= 4


def test_lookalike_in_url_no_findings_for_clean_url():
    urls = ["https://www.example.com/some/random/path"]
    findings = detect_lookalike_in_urls(urls, brands=["microsoft.com", "paypal.com"])
    assert findings == []
