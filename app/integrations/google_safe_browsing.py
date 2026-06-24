import httpx
from app.core.config import settings


async def check_urls(urls: list) -> dict:
    if not settings.GOOGLE_SAFE_BROWSING_API_KEY or not urls:
        return {"error": "GSB key not configured or no URLs"}
    payload = {
        "client": {"clientId": "phishsniffer", "clientVersion": "2.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls]
        }
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={"key": settings.GOOGLE_SAFE_BROWSING_API_KEY},
                json=payload
            )
            return resp.json() if resp.status_code == 200 else {"error": "GSB check failed"}
    except Exception as e:
        return {"error": str(e)}