# CyberChef recipes for phishing triage

Reusable [CyberChef](https://gchq.github.io/CyberChef/) recipes that come up repeatedly during the deep-dive analyses. Paste any of these URLs into a browser; the recipe is encoded in the fragment, no upload needed.

The recipes are CyberChef share-links. To use one: click the link, paste your input into the **Input** pane, the recipe runs.

> **Workflow tip.** For each deep-dive report, copy the recipe link you actually used into the report's `## CyberChef Analysis` section, with one line on what it told you. That's how the resume bullet ("validating detections in CyberChef") becomes literally true and not just claimed.

## 1. Decode base64 + extract printable strings (min length 8)

**Use for:** any base64 blob found in body or attachment, when you want to see the URLs / function names / config hidden inside.

**Recipe:** `From_Base64('A-Za-z0-9+/=', true, false)` → `Strings(8, 'Single byte', 'All printable chars (incl. whitespace)', false)`

**Share URL:** [https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)Strings('Single%20byte',8,'All%20printable%20chars%20(incl.%20whitespace)',false)](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)Strings('Single%20byte',8,'All%20printable%20chars%20(incl.%20whitespace)',false))

## 2. URL-decode + Defang/refang

**Use for:** URLs pulled from `href=` attributes that have been `%XX`-encoded, and to refang `hxxp[://]example[.]com` style obfuscation back to a clickable URL (or vice-versa: defang an active URL before pasting it into a report).

**Recipe:** `URL_Decode()` → `Defang_URL(true, true, true, 'Valid domains and full URLs')`

**Share URL:** [https://gchq.github.io/CyberChef/#recipe=URL_Decode()Defang_URL(true,true,true,'Valid%20domains%20and%20full%20URLs')](https://gchq.github.io/CyberChef/#recipe=URL_Decode()Defang_URL(true,true,true,'Valid%20domains%20and%20full%20URLs'))

## 3. Decode quoted-printable + extract URLs

**Use for:** HTML body parts where `=3D` and `=20` are everywhere — quoted-printable is the standard MIME transfer encoding for `text/html` and obscures URLs from naive grep. Run this then look at the cleaned output.

**Recipe:** `From_Quoted_Printable()` → `Extract_URLs()`

**Share URL:** [https://gchq.github.io/CyberChef/#recipe=From_Quoted_Printable()Extract_URLs(true)](https://gchq.github.io/CyberChef/#recipe=From_Quoted_Printable()Extract_URLs(true))

## 4. Magic byte detection (a.k.a. "what is this attachment really?")

**Use for:** any attachment where the filename extension might be a lie. CyberChef's **Magic** operation walks a tree of operations and reports the most likely format.

**Recipe:** `Magic(3, false, false, '')`

**Share URL:** [https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')](https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,''))

## 5. Decode HTML smuggling JS

**Use for:** small `.html` attachments containing an `atob()` call and a long base64 string — the canonical HTML smuggling pattern. Paste the entire `.html` body and walk through the output.

**Recipe:** `Regular_expression('User defined','atob\\(["\\\']([A-Za-z0-9+/=]+)["\\\']\\)',true,true,false,false,false,false,'List capture groups')` → `From_Base64('A-Za-z0-9+/=', true, false)`

**Share URL:** [https://gchq.github.io/CyberChef/#recipe=Regular_expression('User%20defined','atob%5C(%5C%5C%22%5C%5C%27%5D(%5BA-Za-z0-9%2B/%3D%5D%2B)%5C%5C%22%5C%5C%27%5D%5C)',true,true,false,false,false,false,'List%20capture%20groups')From_Base64('A-Za-z0-9%2B/%3D',true,false)](https://gchq.github.io/CyberChef/#recipe=Regular_expression('User%20defined','atob%5C(%5C%5C%22%5C%5C%27%5D(%5BA-Za-z0-9%2B/%3D%5D%2B)%5C%5C%22%5C%5C%27%5D%5C)',true,true,false,false,false,false,'List%20capture%20groups')From_Base64('A-Za-z0-9%2B/%3D',true,false))

> If the recipe URL above doesn't survive your editor's link parsing, build it locally: open CyberChef, drag in **Regular expression** → set the regex to `atob\(["'](.+?)["']\)`, capture the first group, then drag in **From Base64**.

## 6. Extract attachment hashes

**Use for:** quickly hash an attachment for VirusTotal lookup or to drop the SHA-256 into your report.

**Recipe:** `MD5()` (then swap to `SHA1` / `SHA2('256')` as needed) — easier to use the **Hashing** category in the operations panel directly.
