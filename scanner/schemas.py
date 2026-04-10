from typing import List, Optional
from pydantic import BaseModel, ConfigDict
from datetime import datetime

class DNSSummary(BaseModel):
    a_records: List[str]

class ScanResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    target: str
    scan_timestamp: datetime
    https_enabled: Optional[bool] = None
    http_redirect_to_https: Optional[bool] = None
    certificate_valid: Optional[bool] = None
    certificate_expires_in_days: Optional[int] = None
    certificate_issuer: Optional[str] = None
    dns_summary: DNSSummary
    present_headers: List[str]
    missing_headers: List[str]
    cookie_issues: List[str]
    metadata_exposure: List[str]
    score: int
    severity: str
    recommendations: List[str]

    def to_json_dict(self) -> dict:
        # Convert timestamp to ISO 8601 format string as standard
        data = self.model_dump()
        data['scan_timestamp'] = self.scan_timestamp.isoformat() + "Z" if self.scan_timestamp.tzinfo is None else self.scan_timestamp.isoformat()
        return data
