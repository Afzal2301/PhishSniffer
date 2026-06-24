from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class EmailScanRequest(BaseModel):
    raw_email: str
    scan_name: Optional[str] = None


class URLScanRequest(BaseModel):
    url: str
    scan_name: Optional[str] = None


class AttachmentScanRequest(BaseModel):
    filename: str
    file_content: str
    scan_name: Optional[str] = None


class UnifiedScanRequest(BaseModel):
    raw_email: Optional[str] = None
    urls: Optional[List[str]] = None
    scan_name: Optional[str] = None


class IoC(BaseModel):
    type: str
    value: str


class ScanResult(BaseModel):
    scan_id: Optional[int] = None
    scan_type: str
    scan_name: Optional[str] = None
    risk_score: float
    verdict: str
    narrative: str
    iocs: List[IoC]
    details: dict
    created_at: Optional[datetime] = None


class ScanHistoryOut(BaseModel):
    id: int
    scan_name: Optional[str] = None
    scan_type: str
    risk_score: Optional[float]
    verdict: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}