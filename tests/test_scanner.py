import sys
import os
import time
import pytest
from unittest.mock import Mock, patch

# 프로젝트 루트 디렉토리를 파이썬 경로에 추가
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.append(project_root)

from poc_fuzzmap.scanner import FuzzScanner
from poc_fuzzmap.models import *

def test_sql_injection_detection():
    scanner = FuzzScanner("http://127.0.0.1/index.php?type=title", "search")
    
    # SQL 에러 메시지를 포함한 응답 생성
    mock_response = Mock()
    mock_response.text = "You have an error in your SQL syntax"
    mock_response.status_code = 200
    
    with patch.object(scanner, '_send_payload', return_value=mock_response):
        response = scanner._send_payload("'")
        detections = scanner._analyze_response(
            response,
            500,  # original length
            time.time() - 0.5
        )
        
        sql_detections = [d for d in detections 
                         if d.condition == DetectionType.SQL_ERROR]
        assert len(sql_detections) == 1
        assert sql_detections[0].confidence == 70.0
        assert "SQL syntax" in sql_detections[0].evidence

def test_xss_detection():
    scanner = FuzzScanner("http://127.0.0.1/index.php?type=title", "search")
    
    # Mock response 객체 생성
    mock_response = Mock()
    mock_response.text = "<script>alert(1)</script>"  # XSS 페이로드가 반영된 응답
    mock_response.status_code = 200
    
    # _send_payload 메소드를 mock으로 대체
    with patch.object(scanner, '_send_payload', return_value=mock_response):
        response = scanner._send_payload("<script>alert(1)</script>")
        detections = scanner._analyze_response(
            response,
            500,
            time.time() - 0.5
        )
        
        xss_detections = [d for d in detections 
                         if d.condition == DetectionType.ALERT_TRIGGERED]
        assert len(xss_detections) == 1
        assert xss_detections[0].confidence == 90.0

def test_version_detection():
    scanner = FuzzScanner("http://127.0.0.1/index.php?type=title", "search")
    
    test_cases = [
        ("MySQL version 5.7.44-community", "MySQL", "5.7.44"),
        ("Microsoft SQL Server 2019 (RTM) - 15.0.2000.5", "MSSQL", "15.0.2000.5"),
        ("PostgreSQL 13.2 on x86_64-pc-linux-gnu", "PostgreSQL", "13.2"),
        ("Oracle Database 19c Enterprise Edition Release 19.3.0.0.0", "Oracle", "19.3.0.0.0"),
        ("SQLite version 3.36.0", "SQLite", "3.36.0")
    ]
    
    for test_text, expected_db, expected_version in test_cases:
        mock_response = Mock()
        mock_response.text = test_text
        mock_response.status_code = 200
        
        with patch.object(scanner, '_send_payload', return_value=mock_response):
            response = scanner._send_payload("version check")
            detections = scanner._analyze_response(
                response,
                500,
                time.time() - 0.1
            )
            
            version_detections = [d for d in detections 
                                if d.condition == DetectionType.VERSION_DISCLOSURE]
            
            assert len(version_detections) == 1
            assert version_detections[0].confidence == 100.0
            assert expected_db in version_detections[0].evidence
            assert expected_version in version_detections[0].evidence

def test_response_length_detection():
    scanner = FuzzScanner("http://127.0.0.1/index.php?type=title", "search")
    
    # 길이 비교가 필요한 페이로드
    test_payload = "' or 1=1 -- -;<img src=x>//"
    
    # 원본 응답 길이 설정 (500)
    original_length = 500
    
    # 테스트할 응답 길이들
    test_cases = [
        (1000, True),   # 원본보다 긴 응답 (차이 감지됨)
        (500, False),   # 원본과 같은 길이 (차이 없음)
        (200, True)     # 원본보다 짧은 응답 (차이 감지됨)
    ]
    
    for response_length, should_detect in test_cases:
        mock_response = Mock()
        mock_response.text = "a" * response_length
        mock_response.status_code = 200
        
        with patch.object(scanner, '_send_payload', return_value=mock_response):
            response = scanner._send_payload(test_payload)
            detections = scanner._analyze_response(
                response,
                original_length,
                time.time() - 0.1
            )
            
            length_detections = [d for d in detections 
                               if d.condition == DetectionType.RESPONSE_LENGTH_DIFF]
            
            if should_detect:
                assert len(length_detections) == 1
                assert length_detections[0].confidence == 50.0
                # 응답 길이 차이를 evidence에 포함
                assert str(abs(response_length - original_length)) in length_detections[0].evidence
            else:
                assert len(length_detections) == 0

if __name__ == "__main__":
    pytest.main([__file__])