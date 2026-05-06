from triage.payload_extractor import (
    extract_urls,
    extract_emails,
    extract_ips,
    find_base64_blobs,
    extract_iocs,
)


def test_extract_obfuscated_url():
    text = "Click hxxps://login[.]micros0ft[.]com/auth to confirm."
    urls, obf = extract_urls(text)
    assert "https://login.micros0ft.com/auth" in urls
    assert obf  # original obfuscated form was captured


def test_extract_href_url():
    html = '<a href="https://phish.example/login.php?id=1">click</a>'
    urls, _ = extract_urls(html)
    assert urls == ["https://phish.example/login.php?id=1"]


def test_extract_emails():
    text = "Reach out to attacker@evil-mailer.tk or noreply@example.com"
    emails = extract_emails(text)
    assert "attacker@evil-mailer.tk" in emails
    assert "noreply@example.com" in emails


def test_extract_ips():
    text = "Originating from 198.51.100.7 via relay 8.8.8.8"
    ips = extract_ips(text)
    assert "198.51.100.7" in ips
    assert "8.8.8.8" in ips


def test_find_base64_blob_with_pe_magic():
    # base64 of "MZ\x90\x00..." which is the start of a PE file
    pe_b64 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    hits = find_base64_blobs(pe_b64)
    assert len(hits) == 1
    assert hits[0].magic_label and "PE" in hits[0].magic_label


def test_extract_iocs_e2e_on_synthetic(synthetic_msg):
    from triage.mime_walker import walk
    mime = walk(synthetic_msg)
    rep = extract_iocs(
        body_text=mime.body_text,
        body_html=mime.body_html,
        attachments_bytes=[a.payload for a in mime.attachments],
    )
    assert rep.urls, "should extract at least one URL from the synthetic body"
    assert rep.emails, "should extract email addresses"
    assert any(h.magic_label and "PE" in h.magic_label for h in rep.base64_hits)
