/*
    exec_impersonation.yar
    -----------------------
    Worked example. Read top-to-bottom; each block is annotated.

    YARA rule anatomy:
      meta {}    -- documentation only, ignored by the engine
      strings {} -- the literal/regex/byte patterns to look for
      condition {} -- boolean expression over those strings (and/or filesize, etc.)

    A rule fires when `condition` evaluates to true against a scanned buffer.
    The triage CLI scans:
      - the whole .eml file
      - each MIME body (text/plain + text/html separately)
      - each decoded attachment

    so write conditions that make sense for whichever buffer the rule should hit.
*/

rule exec_impersonation_keywords
{
    meta:
        author      = "phishing-triage-lab"
        description = "Body language consistent with BEC / executive impersonation"
        category    = "exec_impersonation"
        severity    = "medium"
        // attaching MITRE ATT&CK technique IDs makes the rule output more useful in reports
        attck       = "T1566.002"

    strings:
        // Common BEC openers and urgency cues. Case-insensitive ('i' flag).
        $title_ceo       = "CEO" nocase fullword
        $title_cfo       = "CFO" nocase fullword
        $title_president = "President" nocase fullword
        $title_director  = "Managing Director" nocase

        $urgency_quick   = "quick favor" nocase
        $urgency_urgent  = /\bvery urgent\b/ nocase
        $urgency_now     = /\b(right now|right away|immediately)\b/ nocase

        $action_wire     = /\bwire (transfer|payment|fund)/ nocase
        $action_giftcard = /gift\s*cards?/ nocase
        $action_invoice  = "process this invoice" nocase
        $action_secrecy  = /\bdon[' ]?t (tell|share|inform|copy)\b/ nocase

        // BEC actors often ask to be reached by phone instead of email
        $contact_phone   = /\bcall me (on|at)\b/ nocase

    condition:
        // Fire if the email name-drops a title AND uses an urgency or action cue.
        // 1-of plus 1-of avoids matching every neutral mention of "CEO".
        any of ($title_*) and (
            any of ($urgency_*) or
            any of ($action_*)  or
            $contact_phone
        )
}
