/*
    lookalike_domains.yar
    ---------------------
    Detect typo-squat and homoglyph domains in raw email bodies.

    These rules complement the Python `spoof_detector.detect_lookalike()` and
    `detect_lookalike_in_urls()` functions: those score by Levenshtein/homoglyph
    against a brand list at runtime; YARA rules here lock in literal known-bad
    domains that we've observed in real samples and want fast string-matching
    on every future scan.
*/

rule lookalike_domain_strings
{
    meta:
        author      = "phishing-triage-lab"
        description = "Literal lookalike-domain matches (typo-squat / homoglyph)"
        category    = "lookalike_domain"
        severity    = "high"
        attck       = "T1583.001"

    strings:
        // Microsoft brand homoglyphs
        $microsoft_zero  = "micros0ft.com" nocase
        $rnicrosoft      = "rnicrosoft.com" nocase
        $office356       = "office356" nocase   // observed in sample-3026 path

        // Payment / banking
        $paypal_one      = "paypa1.com" nocase
        $paypall         = "paypall.com" nocase

        // Search / mail
        $g00gle          = "g00gle.com" nocase
        $gmai1           = "gmai1.com" nocase

        // Brand-keyword + suffix typosquats observed in this corpus
        $omahasteaks_gry = "omahasteaksgry" nocase  // observed in sample-6467

    condition:
        any of them
}

rule freetier_cloud_origin
{
    meta:
        description = "Email shows fingerprints of free-tier cloud abuse (Azure trial tenants, public GCS buckets) commonly used to host phishing content"
        category    = "infrastructure_abuse"
        severity    = "medium"

    strings:
        // Azure free-trial tenants used as Return-Path. Legit organisations
        // almost never put @*.onmicrosoft.com in Return-Path of marketing mail.
        $rp_onmicrosoft = /Return-Path:[^\r\n]*@[a-z0-9-]+\.onmicrosoft\.com/ nocase

        // Public Google Cloud Storage buckets used to host phish HTML.
        // Pair with a brand-keyword path to reduce FPs.
        $gcs_bucket = "storage.googleapis.com/" nocase

    condition:
        any of them
}
