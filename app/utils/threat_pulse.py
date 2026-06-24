from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text
from app.models.scan import ScanHistory
from datetime import datetime, timedelta, timezone
import json


async def get_ioc_frequency(ioc_value: str, db: AsyncSession) -> dict:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

    result = await db.execute(
        select(func.count()).where(
            ScanHistory.created_at >= cutoff,
            ScanHistory.raw_results.contains(ioc_value)
        )
    )
    count = result.scalar() or 0

    return {
        "ioc": ioc_value,
        "count_24h": count,
        "label": "Novel" if count == 0 else f"Seen {count}x in 24h",
        "is_novel": count == 0
    }


async def enrich_iocs(iocs: list, db: AsyncSession) -> list:
    enriched = []
    for ioc in iocs:
        pulse = await get_ioc_frequency(ioc.value, db)
        enriched.append({
            "type": ioc.type,
            "value": ioc.value,
            "pulse": pulse
        })
    return enriched