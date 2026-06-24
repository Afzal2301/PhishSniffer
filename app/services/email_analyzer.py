import asyncio
import re
import dns.resolver
from email import message_from_string
from email.utils import parseaddr


def _parse_headers(raw_email: str) -> dict:
    msg = message_from_string(raw_email)

    _, from_addr = parseaddr(msg.get("From", ""))
    _, reply_to_addr = parseaddr(msg.get("Reply-To", ""))
    received = msg.get_all("Received") or []

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                    break
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            body = payload.decode("utf-8", errors="ignore") if isinstance(payload, bytes) else (msg.get_payload() or "")
        except Exception:
            body = msg.get_payload() or ""

    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            filename = part.get_filename()
            if filename:
                attachments.append({"filename": filename, "content_type": part.get_content_type()})

    all_auth_results = msg.get_all("Authentication-Results") or []
    arc_auth = msg.get_all("ARC-Authentication-Results") or []

    return {
        "subject": msg.get("Subject", ""),
        "from": from_addr,
        "to": msg.get("To", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "reply_to": reply_to_addr,
        "received": received,
        "x_mailer": msg.get("X-Mailer", "") or msg.get("X-mailer", ""),
        "x_originating_ip": msg.get("X-Originating-IP", ""),
        "content_type": msg.get("Content-Type", ""),
        "return_path": msg.get("Return-Path", ""),
        "all_authentication_results": all_auth_results,
        "arc_authentication_results": arc_auth,
        "received_spf": msg.get("Received-SPF", ""),
        "dkim_signature": msg.get("DKIM-Signature", ""),
        "body_preview": body[:500] if body else "",
        "attachments": attachments
    }


TRUSTED_RECEIVERS = [
    "mx.google.com", "google.com",
    "outlook.com", "hotmail.com", "microsoft.com",
    "yahoo.com", "yahoodns.net",
    "protonmail.ch", "proton.me",
    "amazonses.com", "amazon.com"
]


def _get_trusted_auth_header(all_auth_results: list, received: list) -> str:
    """Select the most relevant Authentication-Results header."""
    if not all_auth_results:
        return ""

    headers_with_score = []

    for header in all_auth_results:
        authserv_match = re.match(r'^([a-zA-Z0-9.\-]+)', header.strip())
        if not authserv_match:
            continue

        authserv_id = authserv_match.group(1).lower()
        is_trusted = any(trusted in authserv_id for trusted in TRUSTED_RECEIVERS)

        score = 0
        if is_trusted:
            score += 10
            for rec in received:
                if authserv_id in rec.lower():
                    score += 5
                    break

        headers_with_score.append((header, score, authserv_id))

    if headers_with_score:
        headers_with_score.sort(key=lambda x: x[1], reverse=True)
        return headers_with_score[0][0]

    return all_auth_results[0] if all_auth_results else ""


def _parse_auth_results(auth_header: str) -> dict:
    """Parse authentication results with better pattern matching."""
    result = {
        "spf": {"pass": False, "detail": "no result"},
        "dkim": {"pass": False, "detail": "no result"},
        "dmarc": {"pass": False, "detail": "no result"}
    }

    if not auth_header:
        return result

    spf_patterns = [
        r'\bspf=([a-z]+)\b',
        r'\bspf\s+([a-z]+)\b',
        r'\|spf=([a-z]+)\b',
    ]
    for pattern in spf_patterns:
        spf_match = re.search(pattern, auth_header.lower())
        if spf_match:
            val = spf_match.group(1)
            result["spf"]["pass"] = (val == "pass")
            result["spf"]["detail"] = val
            break

    dkim_patterns = [
        r'\bdkim=([a-z]+)\b',
        r'\bdkim\s+([a-z]+)\b',
        r'\|dkim=([a-z]+)\b',
    ]
    for pattern in dkim_patterns:
        dkim_match = re.search(pattern, auth_header.lower())
        if dkim_match:
            val = dkim_match.group(1)
            result["dkim"]["pass"] = (val == "pass")
            result["dkim"]["detail"] = val
            break

    dmarc_patterns = [
        r'\bdmarc=([a-z]+)\b',
        r'\bdmarc\s+([a-z]+)\b',
        r'\|dmarc=([a-z]+)\b',
    ]
    for pattern in dmarc_patterns:
        dmarc_match = re.search(pattern, auth_header.lower())
        if dmarc_match:
            val = dmarc_match.group(1)
            result["dmarc"]["pass"] = (val == "pass")
            result["dmarc"]["detail"] = val
            break

    dkim_domain = re.search(r'header\.i=@?([\w.\-]+)', auth_header)
    if dkim_domain:
        result["dkim"]["domain"] = dkim_domain.group(1)

    spf_domain = re.search(r'smtp\.mailfrom=([\w.\-@]+)', auth_header)
    if spf_domain:
        result["spf"]["mailfrom"] = spf_domain.group(1)

    dmarc_policy = re.search(r'\bp=([a-z]+)\b', auth_header.lower())
    if dmarc_policy:
        result["dmarc"]["policy"] = dmarc_policy.group(1)

    return result


def _is_subdomain_or_parent(domain1: str, domain2: str) -> bool:
    """Check if one domain is a subdomain of the other (local, instant)."""
    if not domain1 or not domain2:
        return False
    if domain1 == domain2:
        return True
    if domain1.endswith("." + domain2) or domain2.endswith("." + domain1):
        return True
    return False


def _get_domain_root(domain: str) -> str:
    """Get the root domain (last two parts) for comparison."""
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _check_domain_mismatch(headers: dict) -> dict:
    """Check domain mismatch with subdomain awareness.

    Runs synchronously. Subdomain relationships (microsoft.com ↔ engage.microsoft.com)
    are correctly treated as matching. Unrelated domains are flagged.
    """
    from_addr = headers.get("from", "")
    reply_addr = headers.get("reply_to", "")
    return_path = headers.get("return_path", "").strip("<>")

    from_domain = from_addr.split("@")[-1].strip().lower() if "@" in from_addr else ""
    reply_domain = reply_addr.split("@")[-1].strip().lower() if "@" in reply_addr else ""
    return_domain = return_path.split("@")[-1].strip().lower() if "@" in return_path else ""

    mismatch = False
    if reply_domain and from_domain and from_domain != reply_domain:
        if not _is_subdomain_or_parent(from_domain, reply_domain):
            from_root = _get_domain_root(from_domain)
            reply_root = _get_domain_root(reply_domain)
            if from_root != reply_root:
                mismatch = True

    return_mismatch = False
    if return_domain and from_domain:
        if not _is_subdomain_or_parent(from_domain, return_domain):
            from_root = _get_domain_root(from_domain)
            return_root = _get_domain_root(return_domain)
            return_mismatch = from_root != return_root

    return {
        "from_domain": from_domain,
        "reply_to_domain": reply_domain,
        "return_path_domain": return_domain,
        "mismatch": mismatch,
        "return_path_mismatch": return_mismatch
    }


async def _dns_lookup_spf(domain: str) -> dict:
    if not domain:
        return {"record_exists": False, "error": "No domain"}
    loop = asyncio.get_event_loop()
    try:
        answers = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(domain, "TXT", lifetime=5)
        )
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=spf1"):
                return {"record_exists": True, "record": txt[:120]}
        return {"record_exists": False, "error": "No SPF record found"}
    except Exception as e:
        return {"record_exists": False, "error": str(e)}


async def _dns_lookup_dmarc(domain: str) -> dict:
    if not domain:
        return {"record_exists": False, "error": "No domain"}
    loop = asyncio.get_event_loop()
    try:
        answers = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        )
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                policy = "none"
                if "p=reject" in txt:
                    policy = "reject"
                elif "p=quarantine" in txt:
                    policy = "quarantine"
                return {"record_exists": True, "record": txt[:120], "policy": policy}
        return {"record_exists": False, "error": "No DMARC record"}
    except Exception as e:
        return {"record_exists": False, "error": str(e)}


def _check_suspicious_headers(headers: dict, spf: dict, dkim: dict, dmarc: dict, domain_info: dict) -> list:
    findings = []

    if not headers.get("from"):
        findings.append("Missing From header")
    if not headers.get("message_id"):
        findings.append("Missing Message-ID header")
    if not headers.get("date"):
        findings.append("Missing Date header")

    if spf.get("detail") in ["fail", "softfail", "permerror", "temperror"]:
        findings.append(f"SPF explicit failure: {spf.get('detail')}")

    if dkim.get("detail") in ["fail", "permerror", "temperror"]:
        findings.append("DKIM verification failed")

    if dmarc.get("detail") in ["fail", "reject", "quarantine"]:
        findings.append("DMARC alignment check failed")

    if domain_info["mismatch"]:
        findings.append(
            f"Reply-To domain mismatch: From={domain_info['from_domain']} vs Reply-To={domain_info['reply_to_domain']}"
        )

    if domain_info.get("return_path_mismatch"):
        findings.append(
            f"Return-Path domain differs from sender root: {domain_info['return_path_domain']} vs {domain_info['from_domain']}"
        )

    received = headers.get("received", [])
    if len(received) > 10:
        findings.append(f"High risk delivery routing chain length (Hops: {len(received)})")

    return findings


async def analyze(raw_email: str) -> dict:
    if not raw_email or not raw_email.strip():
        return {
            "headers": {},
            "domain_mismatch": {"mismatch": False},
            "spf": {"pass": False, "detail": "Empty input"},
            "dkim": {"pass": False, "detail": "Empty input"},
            "dmarc": {"pass": False, "detail": "Empty input"},
            "suspicious_findings": ["No email content provided"],
            "auth_score": 0,
            "auth_source": "none"
        }

    headers = _parse_headers(raw_email)
    domain_info = _check_domain_mismatch(headers)
    from_domain = domain_info.get("from_domain", "")

    all_auth_results = headers.get("all_authentication_results", [])
    received = headers.get("received", [])

    trusted_auth_header = _get_trusted_auth_header(all_auth_results, received)

    if trusted_auth_header:
        parsed = _parse_auth_results(trusted_auth_header)

        spf = {
            "pass": parsed["spf"]["pass"],
            "detail": parsed["spf"]["detail"],
            "source": "authentication_header"
        }
        dkim = {
            "pass": parsed["dkim"]["pass"],
            "detail": parsed["dkim"]["detail"],
            "source": "authentication_header"
        }
        dmarc = {
            "pass": parsed["dmarc"]["pass"],
            "detail": parsed["dmarc"]["detail"],
            "source": "authentication_header"
        }
        auth_source = "authentication_header"

        if spf["detail"] == "no result" and dkim["detail"] == "no result" and dmarc["detail"] == "no result":
            spf_dns, dmarc_dns = await asyncio.gather(
                _dns_lookup_spf(from_domain),
                _dns_lookup_dmarc(from_domain)
            )

            spf = {
                "pass": False,
                "detail": "unverified",
                "record_found": spf_dns["record_exists"],
                "source": "dns_fallback"
            }
            dkim = {
                "pass": False,
                "detail": "no signature" if not headers.get("dkim_signature") else "unverified",
                "source": "dns_fallback"
            }
            dmarc = {
                "pass": False,
                "detail": "unverified",
                "record_found": dmarc_dns["record_exists"],
                "policy": dmarc_dns.get("policy", "none"),
                "source": "dns_fallback"
            }
            auth_source = "dns_fallback"

    else:
        spf_dns, dmarc_dns = await asyncio.gather(
            _dns_lookup_spf(from_domain),
            _dns_lookup_dmarc(from_domain)
        )

        spf = {
            "pass": False,
            "detail": "unverified",
            "record_found": spf_dns["record_exists"],
            "source": "dns_fallback"
        }

        dkim = {
            "pass": False,
            "detail": "no signature" if not headers.get("dkim_signature") else "unverified",
            "source": "dns_fallback"
        }

        dmarc = {
            "pass": False,
            "detail": "unverified",
            "record_found": dmarc_dns["record_exists"],
            "policy": dmarc_dns.get("policy", "none"),
            "source": "dns_fallback"
        }
        auth_source = "dns_fallback"

    # --- DNS verification DISABLED ---
    # The local _check_domain_mismatch already handles subdomain relationships correctly.
    # DNS verification was overriding legitimate mismatches when phishing domains
    # fail DNS lookups (which they often do).
    # Keep domain_info exactly as _check_domain_mismatch determined.

    suspicious_findings = _check_suspicious_headers(headers, spf, dkim, dmarc, domain_info)

    auth_score = 0
    if spf.get("pass"):
        auth_score += 1
    if dkim.get("pass"):
        auth_score += 1
    if dmarc.get("pass"):
        auth_score += 1

    return {
        "headers": headers,
        "domain_mismatch": domain_info,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "suspicious_findings": suspicious_findings,
        "auth_score": auth_score,
        "auth_source": auth_source,
        "hop_count": len(received)
    }