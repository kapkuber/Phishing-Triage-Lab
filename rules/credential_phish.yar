/*
    credential_phish.yar
    --------------------
    Hits emails whose body+HTML attachments include classic credential-harvest
    or transactional-lure cues, paired with brand language. Rules below were
    extended after analyzing 5 real samples in this corpus.
*/

rule credential_harvest_login_lure
{
    meta:
        description = "Login/auth lure language typical of credential-harvest kits"
        category    = "credential_phish"
        severity    = "high"
        attck       = "T1566.002"

    strings:
        $verify_account   = /verify (your )?(account|identity|email|password)/ nocase
        $sign_in          = /\bsign[- ]?in\b/ nocase
        $password_expire  = /password (will )?(expire|expired)/ nocase
        $unusual_activity = "unusual sign-in activity" nocase
        $account_locked   = /account (has been |was )?(locked|suspended|disabled)/ nocase
        $update_billing   = /update (your )?(billing|payment) (info|method|details)/ nocase

        $brand_office365  = "office365" nocase
        $brand_office_365 = "office 365" nocase
        $brand_microsoft  = "microsoft" nocase
        $brand_paypal     = "paypal" nocase
        $brand_chase      = "chase" nocase
        $brand_docusign   = "docusign" nocase
        $brand_outlook    = "outlook" nocase

    condition:
        any of ($verify_account, $sign_in, $password_expire, $unusual_activity, $account_locked, $update_billing)
        and any of ($brand_*)
}

rule docusign_document_lure
{
    meta:
        description = "DocuSign-style document-signing lure (sample-1182 pattern)"
        category    = "credential_phish"
        severity    = "high"
        attck       = "T1566.002"

    strings:
        $docusign        = "docusign" nocase
        $review_sign     = /(review|view) (and )?sign/ nocase
        $check_doc       = "check your document" nocase
        $secure_doc      = /(secure|encrypted) (document|file)/ nocase
        $signed_for_you  = "signed for you" nocase
        $envelope_id     = "envelope id" nocase

    condition:
        $docusign and any of ($review_sign, $check_doc, $secure_doc, $signed_for_you, $envelope_id)
}

rule crypto_payout_lure
{
    meta:
        description = "Crypto / DeFi 'rewards waiting' or 'transaction confirmation' lure (samples 182 + 5714)"
        category    = "credential_phish"
        severity    = "high"
        attck       = "T1566.002"

    strings:
        $rewards_waiting    = /rewards (are )?(waiting|available|pending)/ nocase
        $claim_rewards      = /claim (your )?(rewards?|tokens?|airdrop)/ nocase
        $mining_transaction = "mining_transaction" nocase
        $btc_transaction    = /\bbitcoin (transaction|payout|withdrawal)/ nocase
        $wallet_action      = /(connect|verify|secure) (your )?wallet/ nocase

        $brand_aave         = "aave" nocase
        $brand_coinbase     = "coinbase" nocase
        $brand_binance      = "binance" nocase
        $brand_metamask     = "metamask" nocase

    condition:
        any of ($rewards_waiting, $claim_rewards, $mining_transaction, $btc_transaction, $wallet_action)
        // Either pair with a known DeFi brand, OR rely on the action verb alone (high-precision phrasing)
        and (any of ($brand_*) or $mining_transaction or $btc_transaction)
}

rule retail_order_lure
{
    meta:
        description = "Retail/order-tracking lure with urgency cue (sample-6467 pattern)"
        category    = "credential_phish"
        severity    = "medium"

    strings:
        $order_today    = /order (today|now)\b/ nocase
        $shipping_held  = /(shipment|package) (held|delayed|on hold)/ nocase
        $tracking_inv   = "your tracking" nocase
        $confirm_order  = /confirm (your )?(order|shipment|delivery)/ nocase

        $brand_omaha    = "omaha steaks" nocase
        $brand_amazon   = "amazon" nocase
        $brand_fedex    = "fedex" nocase
        $brand_ups      = /\bups\b/ nocase
        $brand_dhl      = /\bdhl\b/ nocase
        $brand_usps     = "usps" nocase

    condition:
        any of ($order_today, $shipping_held, $tracking_inv, $confirm_order)
        and any of ($brand_*)
}
