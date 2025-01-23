import json
import os
import re
import time
import asyncio
import aiohttp
from typing import Dict, List, Any, Optional

class CommonPayloadHandler:
    def __init__(self, timeout: int = 10):
        self._analyzer = ResponseAnalyzer()
        self._classifier = VulnerabilityClassifier()

    # common_payload.py
    async def scan(self, url: str, param_name: str, param_type: str, responses: List[Dict] = None) -> Dict:
        try:
            print(f"Analyzing responses for URL: {url}, Parameter: {param_name}")
            
            if not responses:
                return {"param_name": param_name, "scan_results": []}
            
            results = []
            for response in responses:
                # RequestPayloadHandler의 응답 구조를 CommonPayloadHandler의 구조로 변환
                formatted_response = {
                    "payload_info": {
                        **response.get("payload_info", {}),
                        "payload": response.get("payload_info", {}).get("payload", [])[0] 
                        if isinstance(response.get("payload_info", {}).get("payload"), list) 
                        else response.get("payload_info", {}).get("payload", "")
                    },
                    "response_text": response.get("response_text", ""),  
                    "response_time": response.get("response_time", 0),
                    "alert_triggered": response.get("alert_triggered", False),
                    "alert_message": response.get("alert_message", ""),
                    "response_length_difference": response.get("response_length_difference")
                }
                
                analysis = self._analyzer.analyze_res(formatted_response)
                if analysis:
                    classified = self._classifier.classify_vuln(analysis)
                    if classified:
                        results.append(classified)

            return {
                "param_name": param_name,
                "scan_results": results
            }

        except Exception as e:
            print(f"Error in scan: {str(e)}")
            return {"param_name": param_name, "scan_results": []}

class ResponseAnalyzer:
    def __init__(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        json_path = os.path.join(current_dir, 'config', 'sql_error.json')
        self.sql_patterns = self._load_sql_patterns(json_path) 

    def _load_sql_patterns(self, json_path: str) -> dict:
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                patterns = json.load(f)
            return patterns
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print("[ERROR] SQL patterns load failed:", e)
            return {}
        
    def analyze_res(self, response_info: Dict[str, Any]) -> Dict[str, Any]:
        try:
            # None 체크 추가
            if response_info is None:
                return None

            result = response_info.copy()
            response_text = result.pop('response_text', '')  

            # 취약점 분석 로직
            vulns = result.get("payload_info", {}).get("vulnerabilities", [])
            for vuln in vulns:
                vuln_type = vuln.get("type")
                
                if vuln_type == "sql_injection":
                    check_result = self.check_sqli(
                        response_text,
                        result.get("response_time", 0),
                        result.get("request_info", {})
                    )
                    if check_result and check_result.get("detected"):
                        vuln.update(check_result)
                        
                elif vuln_type == "xss":
                    payload = result.get("payload_info", {}).get("payload", "")
                    check_result = self.check_xss(
                        response_text,
                        payload
                    )
                    if check_result and check_result.get("detected"):
                        vuln.update(check_result)
                        
                elif vuln_type == "ssti":
                    check_result = self.check_ssti(response_text)
                    if check_result and check_result.get("detected"):
                        vuln.update(check_result)
                        
            # Restore response_text
            result["response_text"] = response_text

            return result

        except Exception as e:
            print("[ERROR] Response analysis failed:", e)
            return None

    def check_sqli(self, response: str, response_time: float, request_info: dict = None) -> Dict[str, Any]:
        # 1. SQL 에러 메시지 체크
        for dbms_type, dbms_info in self.sql_patterns.items():
            for pattern in dbms_info.get("patterns", []):
                if match := re.search(pattern, response, re.IGNORECASE):
                    error_context = response[max(0, match.start()-50):min(len(response), match.end()+50)]
                    return {
                        'detected': True,
                        'pattern_type': 'error',
                        'evidence': f'SQL error detected ({dbms_type})',
                        'context': f'{error_context}',
                        'dbms': dbms_type
                    }
        
        # 2. 시간 지연 체크
        if response_time > 5:
            return {
                'detected': True,
                'pattern_type': 'time_delay',
                'evidence': (f'Response delayed: {response_time:.4f} seconds\n'
                             f'Threshold: 5 seconds')
            }

        # 3. Boolean 응답 길이 차이 체크
        if response_length_difference and response_length_difference > 2:
            return {
                'detected': True,
                'pattern_type': 'boolean',
                'evidence': f'Response length difference: {response_length_difference} bytes'
            }

        return {
            'detected': False,
            'pattern_type': None,
            'evidence': None
        }

    def check_xss(self, response_text: str, payload: str) -> Dict[str, Any]:
    # Convert list payload to string if needed
        
        if isinstance(payload, list):
            payload = payload[0]

        # 1. 페이로드에서 완전한 HTML 태그 추출
        tag_pattern = r'<([a-z0-9]+)[^>]*>([^<]*)</\1>'
        if tag_match := re.search(tag_pattern, payload, re.I):
            injected_tag = tag_match.group(0)
            
            # 2. 추출된 태그가 response에 있는지 확인
            if injected_tag in response_text:
                tag_pos = response_text.find(injected_tag)
                context = response_text[max(0, tag_pos-50):min(len(response_text), tag_pos+len(injected_tag)+50)]
                
                # 3. 특수문자 인코딩 여부 확인 
                special_chars = {'<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;'}
                encoding_status = []
                for char, encoded in special_chars.items():
                    if char in injected_tag:
                        if encoded in context:
                            encoding_status.append(f"{char} is HTML encoded")
                        else:
                            encoding_status.append(f"{char} is unencoded")
                
                return {
                    'detected': True,
                    'pattern_type': 'html_injection',
                    'evidence': f'HTML tag was injected: {injected_tag}',
                    'context': f'...{context}...',
                    'encoding_info': ' | '.join(encoding_status) if encoding_status else None
                }

        # 4. 닫히지 않은 태그나 부분 태그 확인
        partial_pattern = r'<[^>]*>'
        if injected_partial := re.search(partial_pattern, payload, re.I):
            partial_tag = injected_partial.group(0)
            if partial_tag in response_text:
                tag_pos = response_text.find(partial_tag)
                context = response_text[max(0, tag_pos-50):min(len(response_text), tag_pos+len(partial_tag)+50)]
                return {
                    'detected': True, 
                    'pattern_type': 'partial_tag_injection',
                    'evidence': f'Partial HTML tag was injected: {partial_tag}',
                    'context': f'...{context}...'
                }

        return {
            'detected': False,
            'pattern_type': None,
            'evidence': None,
            'context': None
        }

    def check_ssti(self, response: str) -> Dict[str, Any]:
        """SSTI 취약점 체크 - 템플릿 표현식 실행 결과가 응답에 있는지 확인"""
        # 1234**3 연산 결과 체크
        if match := re.search(r'\b1879080904\b', response):
            # 결과값 주변 컨텍스트 추출
            expr_context = response[max(0, match.start()-50):min(len(response), match.end()+50)]
            return {
                'detected': True,
                'pattern_type': 'calculation_result',
                'evidence': 'Template expression (1234**3) was evaluated to 1879080904',
                'context': f'{expr_context}'
            }
        
        return {
            'detected': False,
            'pattern_type': None,
            'evidence': None
        }

class VulnerabilityClassifier:
    def __init__(self) -> None:  
        current_dir = os.path.dirname(os.path.abspath(__file__))
        score_path = os.path.join(current_dir, 'config', 'vuln_confidence.json')
        
        try:
            with open(score_path, 'r', encoding='utf-8') as f:
                self.confidence_scores = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print("[WARNING] Vuln confidence config load failed, using default scores.")
            # 기본 confidence scores 설정
            self.confidence_scores = {
                "sql_injection": {"error": 70, "time_delay": 60, "version_leak": 100, "response_diff": 50},
                "xss": {"reflected": 50, "url_encoded": 30, "html_injection": 70},
                "ssti": {"calculation_result": 100}
            }

    def classify_vuln(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        if not analysis_results:  # None 체크 추가
            return {}
            
        result = analysis_results.copy()
        
        for vuln in result.get("payload_info", {}).get("vulnerabilities", []):  
            confidence = self.calc_confidence(
                vuln.get("type", ""), 
                vuln.get("pattern_type", "")  
            )
            vuln["confidence"] = confidence
                
        return result

    def calc_confidence(self, vuln_type: str, pattern_type: str) -> int:
        """취약점 유형과 패턴 유형에 따른 신뢰도 점수 계산"""
        if not vuln_type or not pattern_type:
            return 0
            
        type_scores = self.confidence_scores.get(vuln_type, {})
        return type_scores.get(pattern_type, 0)

class VulnerabilityClassifier:
    def __init__(self) -> None:  
        current_dir = os.path.dirname(os.path.abspath(__file__))
        score_path = os.path.join(current_dir, 'config', 'vuln_confidence.json')
        
        try:
            with open(score_path, 'r') as f:
                self.confidence_scores = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            # 기본 confidence scores 설정
            self.confidence_scores = {
                "sql_injection": {"error": 70, "time_delay": 60, "version_leak": 100, "response_diff": 50},
                "xss": {"reflected": 50, "url_encoded": 30, "html_injection": 70},
                "ssti": {"calculation_result": 100}
            }

    def classify_vuln(self, analysis_results: Dict) -> Dict:
        if not analysis_results:  # None 체크 추가
            return {}
            
        result = analysis_results.copy()
        
        for vuln in result.get("payload_info", {}).get("vulnerabilities", []):  
            confidence = self.calc_confidence(
                vuln.get("type", ""), 
                vuln.get("pattern_type", "")  
            )
            vuln["confidence"] = confidence
                
        return result

    def calc_confidence(self, vuln_type: str, pattern_type: str) -> int:
        """취약점 유형과 패턴 유형에 따른 신뢰도 점수 계산"""
        if not vuln_type or not pattern_type:
            return 0
            
        type_scores = self.confidence_scores.get(vuln_type, {})
        return type_scores.get(pattern_type, 0)


"""테스트"""
if __name__ == "__main__":
   import asyncio
   from fuzzmap.core.handler.payload_request import RequestPayloadHandler

   async def test_common_payload():
       test_url = "http://php.testinvicti.com/artist.php"
       test_param = "id"
       
       request_handler = RequestPayloadHandler(
           payload_files=["common_payload.json"],
           timeout=10,
           max_concurrent=5
       )
       
       payload_responses = await request_handler.send_payloads(
           url=test_url,
           params={test_param: ""},
           method="GET"
       )

       formatted_responses = []
       for response in payload_responses:
           formatted_response = {
               "payload_info": {
                   **response.get("payload_info", {}),
                   "payload": response.get("payload_info", {}).get("payload", [])[0] 
                   if isinstance(response.get("payload_info", {}).get("payload"), list) 
                   else response.get("payload_info", {}).get("payload", "")
               },
               "response_time": response.get("response_time", 0),
               "alert_triggered": response.get("alert_triggered", False),
               "response_length_difference": response.get("response_length_difference")
           }
           
           formatted_responses.append(formatted_response)

       common_handler = CommonPayloadHandler()
       result = await common_handler.scan(
           url=test_url,
           param_name=test_param,
           param_type="GET",
           responses=formatted_responses
       )
       
       print("\n[+] Analysis Results:")
       if result and result.get('scan_results'):
           for scan_result in result['scan_results']:
               print(f"\nPayload: {scan_result['payload_info']['payload']}")
               print(f"Response Length Difference: {scan_result.get('response_length_difference')}")
               for vuln in scan_result['payload_info']['vulnerabilities']:
                   print(f"Type: {vuln.get('type')}")
                   print(f"Confidence: {vuln.get('confidence')}%")
                   if vuln.get('evidence'): print(f"Evidence: {vuln.get('evidence')}")
                   if vuln.get('pattern_type'): print(f"Pattern Type: {vuln.get('pattern_type')}")

   asyncio.run(test_common_payload())