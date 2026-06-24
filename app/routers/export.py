from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.security import require_user
from app.models.user import User
from app.models.scan import ScanHistory
from app.utils.report_generator import generate_pdf, generate_json, generate_html
import json

router = APIRouter(prefix="/export", tags=["export"])


async def _get_scan_result(scan_id: int, user: User, db: AsyncSession) -> dict:
    result = await db.execute(
        select(ScanHistory).where(ScanHistory.id == scan_id, ScanHistory.user_id == user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    iocs = json.loads(scan.iocs or "[]")
    details = json.loads(scan.raw_results or "{}")
    return {
        "scan_id": scan.id,
        "scan_type": scan.scan_type,
        "risk_score": scan.risk_score,
        "verdict": scan.verdict,
        "narrative": scan.narrative,
        "iocs": iocs,
        "details": details,
        "created_at": str(scan.created_at)
    }


@router.get("/{scan_id}/pdf")
async def export_pdf(scan_id: int, db: AsyncSession = Depends(get_db), user: User = Depends(require_user)):
    data = await _get_scan_result(scan_id, user, db)
    pdf_bytes = generate_pdf(data)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=phishsniffer-{scan_id}.pdf"}
    )


@router.get("/{scan_id}/json")
async def export_json(scan_id: int, db: AsyncSession = Depends(get_db), user: User = Depends(require_user)):
    data = await _get_scan_result(scan_id, user, db)
    return Response(
        content=generate_json(data),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=phishsniffer-{scan_id}.json"}
    )


@router.get("/{scan_id}/html")
async def export_html(scan_id: int, db: AsyncSession = Depends(get_db), user: User = Depends(require_user)):
    data = await _get_scan_result(scan_id, user, db)
    return Response(
        content=generate_html(data),
        media_type="text/html",
        headers={"Content-Disposition": f"attachment; filename=phishsniffer-{scan_id}.html"}
    )