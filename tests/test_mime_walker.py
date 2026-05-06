from triage.mime_walker import walk


def test_walk_finds_text_and_attachment(synthetic_msg):
    rep = walk(synthetic_msg)
    # Two leaf parts: the text body and the base64 attachment
    assert len(rep.parts) == 2
    assert rep.body_text.startswith("Hi, please process the wire")
    assert len(rep.attachments) == 1


def test_attachment_metadata(synthetic_msg):
    rep = walk(synthetic_msg)
    att = rep.attachments[0]
    assert att.filename == "invoice.bin"
    assert att.content_type == "application/octet-stream"
    assert att.size > 0
    assert len(att.sha256) == 64
    # Decoded base64 starts with the MZ header (PE executable magic)
    assert att.payload[:2] == b"MZ"
