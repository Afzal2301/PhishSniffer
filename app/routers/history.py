from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.core.database import get_db
from app.core.security import require_user
from app.models.user import User
from app.models.scan import ScanHistory
from app.schemas.scan import ScanHistoryOut
from typing import List, Optional

router = APIRouter(prefix="/history", tags=["history"])


@router.get("/", response_model=List[ScanHistoryOut])
async def get_history(
    skip: int = 0,
    limit: int = 20,
    verdict: Optional[str] = Query(None),
    scan_type: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_user)
):
    query = select(ScanHistory).where(ScanHistory.user_id == user.id)
    if verdict:
        query = query.where(ScanHistory.verdict == verdict)
    if scan_type:
        query = query.where(ScanHistory.scan_type == scan_type)
    query = query.order_by(desc(ScanHistory.created_at)).offset(skip).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{scan_id}")
async def get_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_user)
):
    result = await db.execute(
        select(ScanHistory).where(ScanHistory.id == scan_id, ScanHistory.user_id == user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_user)
):
    result = await db.execute(
        select(ScanHistory).where(ScanHistory.id == scan_id, ScanHistory.user_id == user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    await db.delete(scan)
    await db.commit()
    return {"deleted": True, "id": scan_id}