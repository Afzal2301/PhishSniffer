import httpx
import asyncio
from app.core.config import settings


async def submit_url(url: str) -> dict:
    if not settings.URLSCAN_API_KEY:
        return {"error": "URLScan API key not configured"}
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                "https://urlscan.io/api/v1/scan/",
                headers={"API-Key": settings.URLSCAN_API_KEY, "Content-Type": "application/json"},
                json={"url": url, "visibility": "public"}
            )
            if resp.status_code != 200:
                return {"error": "URLScan submission failed"}
            data = resp.json()
            uuid = data.get("uuid")
            if not uuid:
                return {"error": "No UUID returned"}
            await asyncio.sleep(10)
            result = await client.get(f"https://urlscan.io/api/v1/result/{uuid}/")
            return result.json() if result.status_code == 200 else {"error": "Result fetch failed", "uuid": uuid}
    except Exception as e:
        return {"error": str(e)}


async def search_url(url: str) -> dict:
    if not settings.URLSCAN_API_KEY:
        return {"error": "URLScan API key not configured"}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            result = await client.get(
                "https://urlscan.io/api/v1/search/",
                headers={"API-Key": settings.URLSCAN_API_KEY},
                params={"q": f"page.url:{url}", "size": 1}
            )
            return result.json() if result.status_code == 200 else {"error": "Search failed"}
    except Exception as e:
        return {"error": str(e)}