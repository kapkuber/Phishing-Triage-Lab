/*
    base64_payloads.yar
    -------------------
    Catch base64-encoded executable / document payloads inside email bodies and
    attachments without decoding them. Detecting the encoded magic-bytes prefix
    means we hit on the email *before* anything is decoded by a downstream tool.
*/

rule base64_pe_executable
{
    meta:
        description = "base64-encoded PE executable (MZ header)"
        category    = "base64_payload"
        severity    = "high"
        attck       = "T1027"

    strings:
        // 'TVqQAA' / 'TVoAAA' / 'TVpAAA' are the most common base64 prefixes
        // for an MZ-header-leading PE executable. The exact 4th-6th chars vary
        // with byte alignment but these three cover the common cases.
        $b64_pe_a = "TVqQAA"
        $b64_pe_b = "TVoAAA"
        $b64_pe_c = "TVpAAA"

    condition:
        any of them
}

rule base64_office_document
{
    meta:
        description = "base64-encoded ZIP / OOXML container (Office docx/xlsx/pptx, also .zip)"
        category    = "base64_payload"
        severity    = "medium"

    strings:
        // PK\x03\x04 -> 'UEsDBA' in base64
        $b64_zip = "UEsDBA"

    condition:
        $b64_zip
}

rule base64_pdf_document
{
    meta:
        description = "base64-encoded PDF (%PDF magic) — fired on sample-182's Bitcoin-themed PDF attachment"
        category    = "base64_payload"
        severity    = "medium"

    strings:
        // '%PDF' -> 'JVBERi' in base64
        $b64_pdf = "JVBERi"

    condition:
        $b64_pdf
}

rule html_smuggling_atob_blob
{
    meta:
        description = "HTML smuggling pattern: atob() of a long base64 blob, classic browser-side payload reassembly"
        category    = "base64_payload"
        severity    = "high"
        attck       = "T1027.006"

    strings:
        $atob_call = /atob\s*\(\s*["'][A-Za-z0-9+\/=]{200,}["']/
        $b64_html_doc = "PCFET0NUWVBFIGh0bWw"   // base64 of '<!DOCTYPE html'
        $b64_script = "PHNjcmlwdD4"             // base64 of '<script>'

    condition:
        $atob_call or ($b64_html_doc and $b64_script)
}
