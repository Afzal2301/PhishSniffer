from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from typing import Optional
import asyncio
import json
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.core.security import get_current_user_from_request as get_current_user
from app.models.user import User
from app.models.scan import ScanHistory
from app.schemas.scan import EmailScanRequest, URLScanRequest, UnifiedScanRequest, ScanResult
from app.services import email_analyzer, url_analyzer
from app.services.ioc_extractor import extract as extract_iocs
from app.services.groq_engine import evaluate, _extract_key_signals
from app.integrations import virustotal, abuseipdb, google_safe_browsing, whois_client
from app.utils.threat_pulse import enrich_iocs

router = APIRouter(prefix="/scan", tags=["scan"])


def _filter_scannable_iocs(iocs: list, max_urls: int = 3, max_ips: int = 3) -> tuple:
    from app.services.ioc_extractor import TRUSTED_DOMAINS
    import tldextract

    suspicious_urls = []
    suspicious_ips = []

    for ioc in iocs:
        if ioc.type == "url":
            try:
                ext = tldextract.extract(ioc.value)
                root = ext.registered_domain.lower()
                if root and root not in TRUSTED_DOMAINS:
                    suspicious_urls.append(ioc.value)
            except Exception:
                pass
        elif ioc.type == "ip":
            suspicious_ips.append(ioc.value)

    return suspicious_urls[:max_urls], suspicious_ips[:max_ips]


async def _run_url_typosquat_analysis(urls: list) -> dict:
    url_analyses = {}
    if not urls:
        return url_analyses
    tasks = await asyncio.gather(
        *[url_analyzer.analyze(u) for u in urls[:3]],
        return_exceptions=True
    )
    for u, result in zip(urls[:3], tasks):
        if not isinstance(result, Exception):
            url_analyses[u] = result
    return url_analyses


async def _save_scan(db, user, scan_type, input_data, result, scan_name=None):
    record = ScanHistory(
        user_id=user.id if user else None,
        scan_name=scan_name,
        scan_type=scan_type,
        input_data=input_data[:500],
        risk_score=result.get("risk_score"),
        verdict=result.get("verdict"),
        narrative=result.get("narrative"),
        iocs=json.dumps([i.dict() if hasattr(i, "dict") else i for i in result.get("iocs", [])]),
        raw_results=json.dumps(result.get("details", {}), default=str)
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return record.id


@router.post("/upload-eml", response_model=ScanResult)
async def scan_eml_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_current_user)
):
    if not file.filename.endswith('.eml'):
        raise HTTPException(status_code=400, detail="Only .eml files are accepted")

    content = await file.read()
    try:
        raw_email = content.decode('utf-8', errors='ignore')
    except Exception:
        raise HTTPException(status_code=400, detail="Could not read file")

    email_data = await email_analyzer.analyze(raw_email)
    iocs = extract_iocs(raw_email)
    urls, ips = _filter_scannable_iocs(iocs)

    vt_results, gsb_result, ip_results, url_analyses = await asyncio.gather(
        asyncio.gather(*[virustotal.scan_url(u) for u in urls]) if urls else asyncio.sleep(0),
        google_safe_browsing.check_urls(urls) if urls else asyncio.sleep(0),
        abuseipdb.check_bulk(ips) if ips else asyncio.sleep(0),
        _run_url_typosquat_analysis(urls),
    )

    analysis_data = {
        "email": email_data,
        "filename": file.filename,
        "virustotal": vt_results,
        "google_safe_browsing": gsb_result,
        "abuseipdb": ip_results,
        "url_analyses": url_analyses,
        "ioc_count": len(iocs)
    }

    ai_result = await evaluate(analysis_data)
    enriched_iocs = await enrich_iocs(iocs, db)
    signals = _extract_key_signals(analysis_data)

    from_addr = email_data.get("headers", {}).get("from", "") or file.filename
    scan_name = from_addr if from_addr else file.filename

    result = {
        "scan_type": "email",
        "scan_name": scan_name,
        "risk_score": ai_result["risk_score"],
        "verdict": ai_result["verdict"],
        "narrative": ai_result["narrative"],
        "iocs": [{"type": i["type"], "value": i["value"]} for i in enriched_iocs],
        "intel_scores": signals.get("intel_scores", {}),
        "details": {**analysis_data, "threat_pulse": enriched_iocs}
    }

    scan_id = await _save_scan(db, user, "email", raw_email[:200], result, scan_name)
    result["scan_id"] = scan_id
    return result


@router.post("/email", response_model=ScanResult)
async def scan_email(
    payload: EmailScanRequest,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_current_user)
):
    email_data = await email_analyzer.analyze(payload.raw_email)
    iocs = extract_iocs(payload.raw_email)
    urls, ips = _filter_scannable_iocs(iocs)

    vt_results, gsb_result, ip_results, url_analyses = await asyncio.gather(
        asyncio.gather(*[virustotal.scan_url(u) for u in urls]) if urls else asyncio.sleep(0),
        google_safe_browsing.check_urls(urls) if urls else asyncio.sleep(0),
        abuseipdb.check_bulk(ips) if ips else asyncio.sleep(0),
        _run_url_typosquat_analysis(urls),
    )

    analysis_data = {
        "email": email_data,
        "virustotal": vt_results,
        "google_safe_browsing": gsb_result,
        "abuseipdb": ip_results,
        "url_analyses": url_analyses,
        "ioc_count": len(iocs)
    }

    ai_result = await evaluate(analysis_data)
    enriched_iocs = await enrich_iocs(iocs, db)
    signals = _extract_key_signals(analysis_data)

    from_addr = email_data.get("headers", {}).get("from", "")
    scan_name = payload.scan_name or from_addr or "Email Scan"

    result = {
        "scan_type": "email",
        "scan_name": scan_name,
        "risk_score": ai_result["risk_score"],
        "verdict": ai_result["verdict"],
        "narrative": ai_result["narrative"],
        "iocs": [{"type": i["type"], "value": i["value"]} for i in enriched_iocs],
        "intel_scores": signals.get("intel_scores", {}),
        "details": {**analysis_data, "threat_pulse": enriched_iocs}
    }

    scan_id = await _save_scan(db, user, "email", payload.raw_email[:200], result, scan_name)
    result["scan_id"] = scan_id
    return result


@router.post("/url", response_model=ScanResult)
async def scan_url(
    payload: URLScanRequest,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_current_user)
):
    import re
    import tldextract
    url = payload.url.strip()

    if not url.startswith('http://') and not url.startswith('https://'):
        url = f'https://{url}'

    domain_re = re.compile(
        r'^https?://'
        r'(?:[a-zA-Z0-9\-]+\.)*'
        r'[a-zA-Z0-9\-]+'
        r'\.[a-zA-Z]{2,}'
        r'(?:[/?#].*)?$'
    )
    if not domain_re.match(url):
        raise HTTPException(status_code=400, detail="Invalid URL or domain format")

    ext = tldextract.extract(url)
    if not ext.suffix or not ext.suffix.isalpha():
        raise HTTPException(status_code=400, detail="Invalid domain — TLD contains numbers or invalid characters")
    if not ext.domain:
        raise HTTPException(status_code=400, detail="Could not extract domain from URL")

    url_data, vt_data, gsb_data = await asyncio.gather(
        url_analyzer.analyze(url),
        virustotal.scan_url(url),
        google_safe_browsing.check_urls([url]),
    )

    domain = ext.registered_domain
    whois_data = await whois_client.lookup(domain)
    iocs = extract_iocs(url)

    analysis_data = {
        "url_analysis": url_data,
        "virustotal": vt_data,
        "google_safe_browsing": gsb_data,
        "whois": whois_data
    }

    ai_result = await evaluate(analysis_data)
    enriched_iocs = await enrich_iocs(iocs, db)
    signals = _extract_key_signals(analysis_data)

    scan_name = payload.scan_name or domain or url

    result = {
        "scan_type": "url",
        "scan_name": scan_name,
        "risk_score": ai_result["risk_score"],
        "verdict": ai_result["verdict"],
        "narrative": ai_result["narrative"],
        "iocs": [{"type": i["type"], "value": i["value"]} for i in enriched_iocs],
        "intel_scores": signals.get("intel_scores", {}),
        "details": {**analysis_data, "threat_pulse": enriched_iocs}
    }

    scan_id = await _save_scan(db, user, "url", url, result, scan_name)
    result["scan_id"] = scan_id
    return result


@router.post("/unified", response_model=ScanResult)
async def scan_unified(
    payload: UnifiedScanRequest,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_current_user)
):
    tasks = {}
    raw_text = ""

    if payload.raw_email:
        raw_text += payload.raw_email
        tasks["email"] = email_analyzer.analyze(payload.raw_email)

    if payload.urls:
        for u in payload.urls[:5]:
            raw_text += f" {u}"
            tasks[f"url_{u}"] = url_analyzer.analyze(u)

    results = {}
    if tasks:
        gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for key, res in zip(tasks.keys(), gathered):
            results[key] = res if not isinstance(res, Exception) else {"error": str(res)}

    iocs = extract_iocs(raw_text)
    urls = [ioc.value for ioc in iocs if ioc.type == "url"]
    ips = [ioc.value for ioc in iocs if ioc.type == "ip"]

    intel_tasks = []
    if urls:
        intel_tasks.append(google_safe_browsing.check_urls(urls[:10]))
    if ips:
        intel_tasks.append(abuseipdb.check_bulk(ips[:5]))

    intel_results = await asyncio.gather(*intel_tasks) if intel_tasks else []

    analysis_data = {"modules": results, "intel": intel_results, "ioc_count": len(iocs)}
    ai_result = await evaluate(analysis_data)
    enriched_iocs = await enrich_iocs(iocs, db)
    signals = _extract_key_signals(analysis_data)

    email_result = results.get("email", {})
    from_addr = email_result.get("headers", {}).get("from", "") if isinstance(email_result, dict) else ""
    scan_name = payload.scan_name or from_addr or (payload.urls[0] if payload.urls else "Unified Scan")

    result = {
        "scan_type": "unified",
        "scan_name": scan_name,
        "risk_score": ai_result["risk_score"],
        "verdict": ai_result["verdict"],
        "narrative": ai_result["narrative"],
        "iocs": [{"type": i["type"], "value": i["value"]} for i in enriched_iocs],
        "intel_scores": signals.get("intel_scores", {}),
        "details": {**analysis_data, "threat_pulse": enriched_iocs}
    }

    scan_id = await _save_scan(db, user, "unified", raw_text[:200], result, scan_name)
    result["scan_id"] = scan_id
    return result