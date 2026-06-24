import asyncio

import httpx
from app.core.config import settings


async def scan_url(url: str) -> dict:
    if not settings.VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key not configured"}

    headers = {
        "x-apikey": settings.VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            encode_resp = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url}
            )
            if encode_resp.status_code != 200:
                return {"error": f"VT submit failed: {encode_resp.status_code}"}

            url_id = encode_resp.json()["data"]["id"]

            for attempt in range(3):
                await asyncio.sleep(5)
                result = await client.get(
                    f"https://www.virustotal.com/api/v3/analyses/{url_id}",
                    headers=headers
                )
                if result.status_code == 200:
                    data = result.json()
                    status = data.get("data", {}).get("attributes", {}).get("status", "")
                    if status == "completed":
                        return data
            return data

    except Exception as e:
        return {"error": str(e)}
async def scan_file_hash(file_hash: str) -> dict:
    if not settings.VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key not configured"}

    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY, "Accept": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            result = await client.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers=headers
            )
            return result.json() if result.status_code == 200 else {"error": "Hash not found"}
    except Exception as e:
        return {"error": str(e)}


async def scan_domain(domain: str) -> dict:
    if not settings.VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key not configured"}

    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY, "Accept": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            result = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers=headers
            )
            return result.json() if result.status_code == 200 else {"error": "Domain not found"}
    except Exception as e:
        return {"error": str(e)}


async def scan_ip(ip: str) -> dict:
    if not settings.VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key not configured"}

    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY, "Accept": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            result = await client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers=headers
            )
            return result.json() if result.status_code == 200 else {"error": "IP not found"}
    except Exception as e:
        return {"error": str(e)}