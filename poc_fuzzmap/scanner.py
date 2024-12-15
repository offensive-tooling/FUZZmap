import time
import requests
import re
from typing import List
from poc_fuzzmap.models import *

class FuzzScanner:
    """취약점 스캐너 클래스"""
    
    def __init__(self, url: str, param: str):
        self.url = url
        self.param = param
        self.session = requests.Session()
        self.deep_scan_threshold = 50.0  # 심화 스캔 임계값
        self.current_payload = None  # 현재 페이로드 저장용
        
    def _send_payload(self, payload: str) -> requests.Response:
        """페이로드 전송"""
        self.current_payload = payload  # 현재 페이로드 저장
        params = {self.param: payload}
        return self.session.get(self.url, params=params)
        
    def _analyze_response(self, response: requests.Response, 
                         original_length: int,
                         start_time: float) -> List[Detection]:
        """응답 분석"""
        detections = []
        response_time = time.time() - start_time
        
        # 응답 길이 비교가 필요한 페이로드 패턴
        length_diff_payloads = [
            "a' or 1=1 -- -;<img src=x>//",
            "a' or 1>1 -- -;<img src=x>//"
        ]
        
        # SQL 에러 패턴 정의
        sql_errors = {
            "MySQL": [
                "you have an error in your sql syntax",
                "com.mysql.jdbc.exceptions",
                "org.gjt.mm.mysql",
                "odbc driver does not support",
                "the used select statements have a different number of columns"
            ],
            "MSSQL": [
                "com.microsoft.sqlserver.jdbc",
                "com.microsoft.jdbc",
                "com.inet.tds",
                "com.ashna.jturbo",
                "weblogic.jdbc.mssqlserver",
                "[microsoft]",
                "[sqlserver]",
                "[sqlserver 2000 driver for jdbc]",
                "net.sourceforge.jtds.jdbc",
                "80040e14",
                "800a0bcd",
                "80040e57",
                "all queries in an sql statement containing a union operator must have an equal number of expressions",
                "all queries combined using a union, intersect or except operator must have an equal number of expressions"
            ],
            "Oracle": [
                "oracle.jdbc",
                "sqlstate[hy",
                "ora-00933",
                "ora-06512",
                "sql command not properly ended",
                "ora-00942",
                "ora-29257",
                "ora-00932",
                "query block has incorrect number of result columns",
                "ora-01789"
            ],
            "PostgreSQL": [
                "org.postgresql.util.psqlexception",
                "org.postgresql",
                "each union query must have the same number of columns"
            ],
            "SQLite": [
                "near \".+\": syntax error",
                "sqlite_error",
                "selects to the left and right of union do not have the same number of result columns"
            ],
            "Common": [
                "warning: undefined"
            ]
        }

        # SQL 에러 체크 (신뢰도 70%)
        for db_type, error_patterns in sql_errors.items():
            for pattern in error_patterns:
                if pattern.lower() in response.text.lower():
                    # Common 에러는 DB 종류를 표시하지 않음
                    error_msg = (f"SQL error pattern detected: {pattern}" 
                               if db_type == "Common" 
                               else f"SQL error pattern detected ({db_type}): {pattern}")
                    detections.append(Detection(
                        DetectionType.SQL_ERROR,
                        70.0,
                        error_msg
                    ))
                    break
        
        # DB 버전 노출 체크 (신뢰도 100%)
        version_patterns = {
            "MSSQL": [
                r"Microsoft SQL Server.*?(\d+\.[\d\.]+)",
                r"SQL Server.*?(\d+\.[\d\.]+)",
                r"@@version.*?(\d+\.[\d\.]+)",
            ],
            "MySQL": [
                r"(\d+\.\d+\.\d+)-MariaDB",
                r"MySQL.*?(\d+\.[\d\.]+)",
                r"@@version.*?(\d+\.[\d\.]+)",
                r"mysql_version.*?(\d+\.[\d\.]+)",
                r"(\d+\.\d+\.\d+)-log",
                r"(\d+\.\d+\.\d+)-\w+",  # 예: 5.7.44-log, 8.0.35-community
            ],
            "PostgreSQL": [
                r"PostgreSQL.*?(\d+\.[\d\.]+)",
                r"Postgres.*?(\d+\.[\d\.]+)",
                r"version\(\).*?(\d+\.[\d\.]+)",
                r"pgsql.*?(\d+\.[\d\.]+)",
            ],
            "Oracle": [
                r"Oracle Database.*?(\d+\.[\d\.]+)",
                r"Oracle.*?Version.*?(\d+\.[\d\.]+)",
                r"Oracle.*?Release.*?(\d+\.[\d\.]+)",
                r"TNS for \w+.*?(\d+\.[\d\.]+)",
            ],
            "SQLite": [
                r"SQLite version (\d+\.[\d\.]+)",
                r"SQLite3.*?(\d+\.[\d\.]+)",
            ]
        }
        
        for db_type, patterns in version_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, response.text, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    detections.append(Detection(
                        DetectionType.VERSION_DISCLOSURE,
                        100.0,
                        f"Database version disclosed ({db_type}): {version}"
                    ))
                    break
        
        # 시간 지연 체크 (신뢰도 60%)
        delay_patterns = {
            "WAITFOR DELAY": "MSSQL",
            "SLEEP": "MySQL",
            "pg_sleep": "PostgreSQL",
            "DBMS_LOCK.SLEEP": "Oracle",
            "DBMS_SESSION.SLEEP": "Oracle"
        }
        
        if response_time > 3:
            db_type = None
            for pattern, db in delay_patterns.items():
                if pattern.lower() in response.text.lower():
                    db_type = db
                    break
                    
            detections.append(Detection(
                DetectionType.TIME_DELAY,
                60.0,
                f"Response delayed by {response_time:.1f}s" + 
                (f" ({db_type} time-based)" if db_type else "")
            ))
            
        # 응답 길이 차이 체크 (신뢰도 50%)
        if self.current_payload in length_diff_payloads:
            if abs(len(response.text) - original_length) > 500:
                detections.append(Detection(
                    DetectionType.RESPONSE_LENGTH_DIFF,
                    50.0,
                    f"Response length differs significantly (original: {original_length}, current: {len(response.text)})"
                ))
            
        # XSS alert 체크 (신뢰도 90%)
        if ("alert(1)" in response.text or "alert(2)" in response.text or 
            "alert(6)" in response.text) and not response.text.startswith("%"):
            detections.append(Detection(
                DetectionType.ALERT_TRIGGERED,
                90.0,
                "Alert function execution confirmed"
            ))
            
        # HTML 태그 필터링 체크 (신뢰도 50%)
        if any(tag in response.text for tag in 
               ["<script", "<img", "<svg", "<iframe", "<h1"]):
            detections.append(Detection(
                DetectionType.HTML_TAG_UNFILTERED,
                50.0,
                "HTML tags not filtered"
            ))
            
        # SSTI 연산 결과 체크 (신뢰도 100%)
        if "49" in response.text and any(expr in response.text for expr in 
                                       ["7*7", "#{7*7}", "${7*7}"]):
            detections.append(Detection(
                DetectionType.CALCULATION_RESULT,
                100.0,
                "SSTI calculation result (7*7=49) found"
            ))
            
        return detections

    def needs_deep_scan(self, detections: List[Detection]) -> bool:
        """심화 스캔 필요 여부 확인"""
        return any(d.confidence >= self.deep_scan_threshold for d in detections)