import httpx
from app.core.config import settings


async def check_ip(ip: str) -> dict:
    if not settings.ABUSEIPDB_API_KEY:
        return {"error": "AbuseIPDB API key not configured"}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            result = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
            )
            return result.json() if result.status_code == 200 else {"error": "IP check failed"}
    except Exception as e:
        return {"error": str(e)}


async def check_bulk(ips: list) -> list:
    import asyncio
    if not ips:
        return []
    return await asyncio.gather(*[check_ip(ip) for ip in ips])