/*
    suspicious_attachments.yar
    --------------------------
    Flag attachment filenames and types that are over-represented in phishing.
    These rules run against the raw .eml — the filename and Content-Disposition
    headers stay in plaintext even when the payload is base64-encoded.
*/

rule suspicious_attachment_extensions
{
    meta:
        description = "Attachment filename ends in a high-risk extension"
        category    = "suspicious_attachment"
        severity    = "medium"

    strings:
        $f_html  = /filename=\"?[^\"\r\n]+\.html?\"?/ nocase
        $f_iso   = /filename=\"?[^\"\r\n]+\.iso\"?/ nocase
        $f_img   = /filename=\"?[^\"\r\n]+\.img\"?/ nocase
        $f_lnk   = /filename=\"?[^\"\r\n]+\.lnk\"?/ nocase
        $f_js    = /filename=\"?[^\"\r\n]+\.js\"?/ nocase
        $f_vbs   = /filename=\"?[^\"\r\n]+\.vbs\"?/ nocase
        $f_zip   = /filename=\"?[^\"\r\n]+\.zip\"?/ nocase
        $f_rar   = /filename=\"?[^\"\r\n]+\.rar\"?/ nocase
        $f_xll   = /filename=\"?[^\"\r\n]+\.xll\"?/ nocase
        $f_one   = /filename=\"?[^\"\r\n]+\.one\"?/ nocase

    condition:
        any of them
}

rule double_extension_attachment
{
    meta:
        description = "Filename uses a fake-document double extension (e.g. invoice.pdf.exe)"
        category    = "suspicious_attachment"
        severity    = "high"

    strings:
        $double = /filename=\"?[^\"\r\n]+\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|html?|jpg|png)\.(exe|scr|bat|cmd|js|vbs|lnk|hta)\"?/ nocase

    condition:
        $double
}

rule pdf_with_finance_lure
{
    meta:
        description = "PDF attachment with a finance / crypto / invoice-themed filename — classic payload-vehicle pattern (sample-182)"
        category    = "suspicious_attachment"
        severity    = "medium"

    strings:
        $pdf_bitcoin   = /filename=\"?[^\"\r\n]*(bitcoin|btc|crypto|wallet)[^\"\r\n]*\.pdf\"?/ nocase
        $pdf_invoice   = /filename=\"?[^\"\r\n]*(invoice|receipt|payment|wire|transfer)[^\"\r\n]*\.pdf\"?/ nocase
        $pdf_transaction = /filename=\"?[^\"\r\n]*transaction[^\"\r\n]*\.pdf\"?/ nocase

    condition:
        any of them
}
