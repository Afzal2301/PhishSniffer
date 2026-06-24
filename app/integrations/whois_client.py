import asyncio
import whois


async def lookup(domain: str) -> dict:
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(None, whois.whois, domain)
        return {
            "domain_name": result.domain_name,
            "registrar": result.registrar,
            "creation_date": str(result.creation_date),
            "expiration_date": str(result.expiration_date),
            "name_servers": result.name_servers,
            "status": result.status,
            "country": result.country
        }
    except Exception as e:
        return {"error": str(e)}