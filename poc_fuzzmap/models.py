from dataclasses import dataclass
from enum import Enum
from typing import List

class VulnType(Enum):
    """취약점 유형 정의"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss" 
    SSTI = "ssti"

class DetectionType(Enum):
    """탐지 유형 정의"""
    SQL_ERROR = "sql_error"
    TIME_DELAY = "time_delay"
    VERSION_DISCLOSURE = "version_disclosure"
    RESPONSE_LENGTH_DIFF = "response_length_diff"
    ALERT_TRIGGERED = "alert_triggered"
    HTML_TAG_UNFILTERED = "html_tag_unfiltered"
    CALCULATION_RESULT = "calculation_result"

@dataclass
class Detection:
    """취약점 탐지 정보"""
    condition: DetectionType
    confidence: float
    evidence: str

@dataclass 
class Vulnerability:
    """취약점 정보"""
    type: VulnType
    detection: Detection

@dataclass
class Payload:
    """페이로드 정보"""
    value: str
    description: str
    vulnerabilities: List[Vulnerability] 