from sqlalchemy import Column, Integer, String, Float, DateTime, Text, ForeignKey, func
from app.core.database import Base


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    scan_name = Column(String(200), nullable=True)
    scan_type = Column(String(20), nullable=False)
    input_data = Column(Text, nullable=False)
    risk_score = Column(Float, nullable=True)
    verdict = Column(String(20), nullable=True)
    narrative = Column(Text, nullable=True)
    iocs = Column(Text, nullable=True)
    raw_results = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())