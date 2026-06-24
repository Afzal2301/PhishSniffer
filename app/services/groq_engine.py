from groq import AsyncGroq
from app.core.config import settings
import json
import re

client = AsyncGroq(api_key=settings.GROQ_API_KEY)


def _extract_key_signals(data: dict) -> dict:
    signals = {}
    intel_scores = {}

    if "email" in data:
        email = data["email"]
        signals["email_auth"] = {
            "spf": email.get("spf", {}).get("pass"),
            "dkim": email.get("dkim", {}).get("pass"),
            "dmarc": email.get("dmarc", {}).get("pass"),
            "domain_mismatch": email.get("domain_mismatch", {}).get("mismatch"),
            "return_path_mismatch": email.get("domain_mismatch", {}).get("return_path_mismatch", False),
            "from_domain": email.get("domain_mismatch", {}).get("from_domain"),
            "reply_to_domain": email.get("domain_mismatch", {}).get("reply_to_domain"),
            "auth_score": email.get("auth_score"),
            "suspicious_findings": email.get("suspicious_findings", [])
        }

    if "virustotal" in data:
        vt = data["virustotal"]
        if isinstance(vt, dict) and "data" in vt:
            stats = vt.get("data", {}).get("attributes", {}).get("stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) or 1
            intel_scores["virustotal"] = {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "detection_rate": round((malicious + suspicious) / total * 100, 1)
            }
        elif isinstance(vt, list):
            combined = {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
            for item in vt:
                if isinstance(item, dict) and "data" in item:
                    s = item.get("data", {}).get("attributes", {}).get("stats", {})
                    for k in combined:
                        combined[k] += s.get(k, 0)
            total = sum(combined.values()) or 1
            combined["detection_rate"] = round(
                (combined["malicious"] + combined["suspicious"]) / total * 100, 1
            )
            intel_scores["virustotal"] = combined
        else:
            intel_scores["virustotal"] = {"error": "unavailable"}

    if "google_safe_browsing" in data:
        gsb = data["google_safe_browsing"]
        matches = gsb.get("matches", []) if isinstance(gsb, dict) else []
        intel_scores["google_safe_browsing"] = {
            "threats_found": len(matches),
            "threat_types": list({m.get("threatType") for m in matches if isinstance(m, dict)})
        }

    if "abuseipdb" in data:
        raw = data["abuseipdb"]
        if isinstance(raw, list) and raw:
            ip_scores = []
            for r in raw[:5]:
                if isinstance(r, dict) and "data" in r:
                    d = r["data"]
                    ip_scores.append({
                        "ip": d.get("ipAddress"),
                        "abuse_score": d.get("abuseConfidenceScore", 0),
                        "total_reports": d.get("totalReports", 0),
                        "country": d.get("countryCode")
                    })
            intel_scores["abuseipdb"] = ip_scores

    if "whois" in data:
        w = data["whois"]
        if isinstance(w, dict):
            signals["whois"] = {
                "registrar": w.get("registrar"),
                "creation_date": str(w.get("creation_date", ""))[:50],
                "country": w.get("country")
            }

    if "url_analysis" in data:
        ua = data["url_analysis"]
        raw_typo_findings = ua.get("typosquatting", {}).get("findings", [])

        if raw_typo_findings:
            typo_detected = True
            typo_summary = f"YES — {len(raw_typo_findings)} finding(s): {', '.join(raw_typo_findings)}"
        else:
            typo_detected = False
            typo_summary = "NO — no typosquatting detected"
            raw_typo_findings = []

        signals["url"] = {
            "domain": ua.get("domain"),
            "scheme": ua.get("scheme"),
            "suspicious_tld": ua.get("suspicious_tld"),
            "homograph_detected": ua.get("homograph_detected"),
            "typosquatting_detected": typo_detected,
            "typosquatting_summary": typo_summary,
            "typo_findings": raw_typo_findings,
            "redirect_count": ua.get("redirects", {}).get("redirect_count", 0),
            "final_url": ua.get("redirects", {}).get("final_url")
        }

    # Extract typosquat findings from URLs found inside email body
    if "url_analyses" in data and data["url_analyses"]:
        typo_findings = []
        suspicious_tld_found = []
        homograph_found = []

        for url, ua in data["url_analyses"].items():
            if not isinstance(ua, dict):
                continue
            typo = ua.get("typosquatting", {})
            if typo.get("detected"):
                typo_findings.extend(typo.get("findings", []))
            if ua.get("suspicious_tld"):
                suspicious_tld_found.append(ua.get("domain", url))
            if ua.get("homograph_detected"):
                homograph_found.append(url)

        if typo_findings or suspicious_tld_found or homograph_found:
            signals["email_url_threats"] = {
                "detected": True,
                "typosquatting_findings": typo_findings,
                "suspicious_tld_domains": suspicious_tld_found,
                "homograph_urls": homograph_found
            }
        else:
            signals["email_url_threats"] = {"detected": False}

    if "ioc_count" in data:
        signals["ioc_context"] = {
            "total_extracted": data["ioc_count"],
            "note": "High IOC count alone does not indicate threat."
        }

    if "modules" in data:
        signals["modules_summary"] = list(data["modules"].keys())

    signals["intel_scores"] = intel_scores
    return signals


def _build_prompt(signals: dict) -> str:
    has_email = "email_auth" in signals
    has_url = "url" in signals

    if has_email and not has_url:
        scan_type = "EMAIL ONLY"
        step1 = "Step 1 - Email Authentication: Check spf, dkim, dmarc values (true=pass, false=fail). All three passing is strong legitimacy."
        step3 = (
            "Step 3 - Email Structure: Check domain_mismatch boolean. Subdomain relationships are NORMAL. "
            "Also check email_url_threats — if detected=true, URLs inside the email body contain typosquatting "
            "or suspicious TLDs which is a strong malicious indicator."
        )
        clean_rule = "If ALL true: spf=true, dkim=true, dmarc=true, VT malicious=0, VT suspicious=0, GSB threats=0, AbuseIPDB max score under 20, domain_mismatch=false, email_url_threats.detected=false → score 0-20, verdict Clear"
        mid_rule = "If ONLY ONE minor signal is off and no threat intel hits → score 21-70, verdict Suspicious"
        high_rule = (
            "If ANY of these → score 71-100, verdict Malicious:\n"
            "  - ALL THREE auth fail: spf=false AND dkim=false AND dmarc=false\n"
            "  - domain_mismatch=true AND at least one auth failure\n"
            "  - VT malicious above 0\n"
            "  - GSB threats_found above 0\n"
            "  - AbuseIPDB abuse_score above 50\n"
            "  - email_url_threats.detected=true\n"
            "IMPORTANT: Complete auth failure alone is sufficient for Malicious. "
            "email_url_threats detected means URLs inside the email are actively typosquatting known brands."
        )
        forbidden = "NEVER mention URL structure outside of email_url_threats. NEVER mention typosquatting unless email_url_threats.detected=true."

    elif has_url and not has_email:
        scan_type = "URL ONLY"
        step1 = "Step 1 - No email headers exist. Do NOT mention SPF, DKIM, DMARC, or domain mismatch at all."
        step3 = (
            "Step 3 - URL Structure: Read these exact boolean values from the signals:\n"
            "  typosquatting_detected: if FALSE say 'no typosquatting detected' and stop.\n"
            "  homograph_detected: if FALSE say 'no homograph detected'.\n"
            "  suspicious_tld: if FALSE say 'no suspicious TLD'.\n"
            "  scheme: https is safe, http is a minor risk flag.\n"
            "  redirect_count: mention only if above 3."
        )
        clean_rule = "If ALL true: VT malicious=0, VT suspicious=0, GSB threats=0, AbuseIPDB max under 20, typosquatting_detected=false, homograph_detected=false, suspicious_tld=false, scheme=https → score 0-20, verdict Clear"
        mid_rule = "If ANY one signal is off but nothing confirmed malicious → score 21-70, verdict Suspicious"
        high_rule = "If multiple threat intel hits OR typosquatting_detected=true AND homograph_detected=true → score 71-100, verdict Malicious"
        forbidden = "NEVER mention SPF, DKIM, DMARC, email headers, or domain mismatch."

    else:
        scan_type = "COMBINED EMAIL AND URL"
        step1 = "Step 1 - Email Authentication: Check spf, dkim, dmarc if email_auth exists. If not present skip."
        step3 = (
            "Step 3 - Structure: For email check domain_mismatch and email_url_threats. "
            "For URL read typosquatting_detected boolean. Check homograph_detected, suspicious_tld, scheme."
        )
        clean_rule = "If all signals clean: auth passes, VT clean, GSB clean, AbuseIPDB under 20, no domain mismatch, typosquatting_detected=false, email_url_threats.detected=false → score 0-20, verdict Clear"
        mid_rule = "If ANY one signal is off but nothing confirmed malicious → score 21-70, verdict Suspicious"
        high_rule = "If multiple threat intel hits OR auth fails AND structural anomalies → score 71-100, verdict Malicious"
        forbidden = "Only mention signals that actually exist in the data."

    signals_json = json.dumps(signals, indent=2, default=str)

    return (
        f"You are a senior SOC analyst. This is a {scan_type} scan.\n\n"
        f"READ THE DATA BELOW. DO NOT USE YOUR OWN KNOWLEDGE. ONLY USE THE VALUES PROVIDED.\n\n"
        f"{step1}\n\n"
        f"Step 2 - Threat Intel: Read exact values from intel_scores.\n"
        f"  VirusTotal: check malicious and suspicious counts only.\n"
        f"  Google Safe Browsing: check threats_found count.\n"
        f"  AbuseIPDB: check abuse_score per IP. Score of 0 means clean.\n\n"
        f"{step3}\n\n"
        f"Step 4 - Apply scoring rules strictly:\n"
        f"  {clean_rule}\n"
        f"  {mid_rule}\n"
        f"  {high_rule}\n\n"
        f"HARD RULES:\n"
        f"  {forbidden}\n"
        f"  typosquatting_detected is a boolean — if false there is NO typosquatting.\n"
        f"  IOC count is irrelevant to scoring.\n"
        f"  AbuseIPDB score of 0 means clean.\n"
        f"  Undetected on VirusTotal is irrelevant.\n\n"
        f"Signals:\n{signals_json}\n\n"
        f"Return ONLY this JSON, no markdown:\n"
        f'{{"reasoning": "3-5 sentences using only values from the data. Be direct and specific.", '
        f'"risk_score": <integer 0-100>, '
        f'"verdict": "<Clear|Suspicious|Malicious>"}}'
    )


def _compute_deterministic_score(signals: dict) -> tuple:
    score = 0
    reasons = []

    if "email_auth" in signals:
        auth = signals["email_auth"]
        spf = auth.get("spf", True)
        dkim = auth.get("dkim", True)
        dmarc = auth.get("dmarc", True)
        mismatch = auth.get("domain_mismatch", False)

        if not dmarc and not spf and not dkim:
            score += 45
            reasons.append("Complete auth failure — SPF, DKIM, and DMARC all failed")
        elif not dmarc:
            score += 35
            reasons.append("DMARC enforcement failure — domain mismatch or spoofing attempt")
        elif not spf or not dkim:
            score += 15
            reasons.append("Partial infrastructure auth failure (SPF or DKIM failed)")

        if mismatch:
            score += 35
            from_d = auth.get("from_domain", "Unknown")
            reply_d = auth.get("reply_to_domain", "Unknown")
            reasons.append(f"Domain mismatch: From {from_d} vs Reply-To {reply_d}")

    has_confirmed_ioc = False
    intel = signals.get("intel_scores", {})

    vt = intel.get("virustotal", {})
    if isinstance(vt, dict) and not vt.get("error"):
        malicious = int(vt.get("malicious", 0))
        suspicious = int(vt.get("suspicious", 0))
        if malicious >= 3:
            has_confirmed_ioc = True
            reasons.append(f"VirusTotal: Confirmed malicious threat ({malicious} engines)")
        elif malicious > 0:
            score += min(30, malicious * 10)
            reasons.append(f"VirusTotal: {malicious} malicious engine detections")
        elif suspicious > 0:
            score += 10
            reasons.append(f"VirusTotal: {suspicious} suspicious engine detections")

    gsb = intel.get("google_safe_browsing", {})
    if isinstance(gsb, dict) and gsb.get("threats_found", 0) > 0:
        has_confirmed_ioc = True
        reasons.append("Google Safe Browsing: URL matches active malicious campaign")

    abuse = intel.get("abuseipdb", [])
    if isinstance(abuse, list) and abuse:
        max_score = max((int(a.get("abuse_score", 0)) for a in abuse), default=0)
        if max_score >= 90:
            score += 35
            reasons.append(f"AbuseIPDB: Critical sender IP abuse confidence {max_score}/100")
        elif max_score >= 50:
            score += 20
            reasons.append(f"AbuseIPDB: High sender IP abuse confidence {max_score}/100")

    if "url" in signals:
        url = signals["url"]
        if url.get("typosquatting_detected"):
            score += 35
            reasons.append("Typosquatting lookalike domain detected")
        if url.get("homograph_detected"):
            score += 35
            reasons.append("Internationalized homograph spoofing detected")
        if url.get("suspicious_tld"):
            score += 15
            reasons.append("Suspicious TLD detected")
        if url.get("scheme") == "http":
            score += 5
            reasons.append("Unencrypted HTTP scheme")

    # Email body URL threat analysis
    if "email_url_threats" in signals and signals["email_url_threats"].get("detected"):
        threats = signals["email_url_threats"]
        if threats.get("typosquatting_findings"):
            score += 30
            reasons.append(f"Typosquatting URLs in email body: {', '.join(threats['typosquatting_findings'][:2])}")
        if threats.get("suspicious_tld_domains"):
            score += 15
            reasons.append(f"Suspicious TLD in email body URLs: {', '.join(threats['suspicious_tld_domains'][:2])}")
        if threats.get("homograph_urls"):
            score += 30
            reasons.append(f"Homograph attack URLs in email body")

    score = max(0, min(100, score))

    if has_confirmed_ioc:
        score = max(score, 85)

    return score, reasons


async def evaluate(analysis_data: dict) -> dict:
    try:
        signals = _extract_key_signals(analysis_data)
        det_score, det_reasons = _compute_deterministic_score(signals)

        prompt = _build_prompt(signals)

        response = await client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
            max_tokens=600
        )

        content = response.choices[0].message.content.strip()
        if content.startswith("```"):
            content = re.sub(r"```[a-z]*", "", content).replace("```", "").strip()

        result = json.loads(content)
        reasoning = result.get("reasoning", "Analysis unavailable.")

        has_url = "url" in signals
        has_email = "email_auth" in signals

        actual_typo_detected = signals.get("url", {}).get("typosquatting_detected", False)
        email_url_threats = signals.get("email_url_threats", {}).get("detected", False)

        hallucinated_typo_words = ["typosquat", "typo of", "lookalike", "typo detected"]
        if any(w in reasoning.lower() for w in hallucinated_typo_words) and not actual_typo_detected and not email_url_threats:
            reasoning = re.sub(
                r'[^.]*\b(?:typosquat|typo of|lookalike|typo detected)\b[^.]*\.',
                '', reasoning, flags=re.IGNORECASE
            ).strip()
            if len(reasoning) < 50:
                reasoning = "No threats detected. All threat intelligence sources returned clean results."

        if has_url and not has_email:
            for word in ["spf", "dkim", "dmarc", "domain mismatch", "email header"]:
                if word in reasoning.lower():
                    reasoning = re.sub(
                        rf'[^.]*\b{re.escape(word)}\b[^.]*\.', '',
                        reasoning, flags=re.IGNORECASE
                    ).strip()

        score = det_score

        if score <= 20:
            verdict = "Clear"
        elif score <= 70:
            verdict = "Suspicious"
        else:
            verdict = "Malicious"

        return {
            "risk_score": score,
            "verdict": verdict,
            "narrative": reasoning.strip()
        }

    except json.JSONDecodeError:
        signals = _extract_key_signals(analysis_data)
        score, reasons = _compute_deterministic_score(signals)
        verdict = "Clear" if score <= 20 else "Suspicious" if score <= 70 else "Malicious"
        return {
            "risk_score": score,
            "verdict": verdict,
            "narrative": ". ".join(reasons) + "." if reasons else "Analysis completed."
        }
    except Exception as e:
        signals = _extract_key_signals(analysis_data)
        score, reasons = _compute_deterministic_score(signals)
        verdict = "Clear" if score <= 20 else "Suspicious" if score <= 70 else "Malicious"
        return {
            "risk_score": score,
            "verdict": verdict,
            "narrative": f"AI narrative unavailable. {'. '.join(reasons)}." if reasons else f"AI engine error: {str(e)}"
        }