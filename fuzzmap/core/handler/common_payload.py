import json
import os
import re
import time 
import asyncio
import aiohttp
from typing import Dict, List, Optional

class CommonPayloadSender:
    def __init__(self, timeout: int = 10) -> None:
        self.timeout: int = timeout
        self.common_payloads: list[dict] = []

        current_dir = os.path.dirname(os.path.abspath(__file__))
        payload_path = os.path.join(current_dir, 'payloads', 'common_payload.json')
        self.load_common_payloads(payload_path)

    def load_common_payloads(self, file_path: str) -> None:
        try:
            if not os.path.exists(file_path):
                self.common_payloads = []
                return
                
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

                if not isinstance(data, dict) or "payloads" not in data: 
                    self.common_payloads = []
                    return

                processed_payloads = []
                for payload_entry in data["payloads"]:
                    if isinstance(payload_entry["payload"], list):  
                        for p in payload_entry["payload"]:
                            processed_payloads.append({
                                "payload": p,
                                "description": payload_entry["description"],
                                "vulnerabilities": payload_entry["vulnerabilities"]
                            })
                    else:  
                        processed_payloads.append(payload_entry)
                
                self.common_payloads = processed_payloads                
        except Exception as e:
            self.common_payloads = []

    def _prepare_request(self, url: str, param_name: str, payload: str, method: str) -> dict:
        """요청 정보를 안전하게 준비"""
        if method.upper() == "GET":
            # GET 요청의 경우 URL에 파라미터 추가
            if "?" in url:
                final_url = f"{url}&{param_name}={payload}"
            else:
                final_url = f"{url}?{param_name}={payload}"

            print(f"Prepared URL: {final_url}")  # 디버깅용
                
            return {
                "method": "GET",
                "url": final_url,
                "params": None,
                "data": None,
                "headers": {"User-Agent": "CommonPayloadSender"}
            }
        else:
            # POST 요청 처리
            return {
                "method": "POST",
                "url": url,
                "params": None,
                "data": {param_name: payload},
                "headers": {
                    "Content-Type": "application/json",
                    "User-Agent": "CommonPayloadSender"
                }
            }

    async def _submit_request(self, url: str, param_name: str, payload: str, method: str, payload_info: dict) -> dict:
        """HTTP 요청 전송 및 응답 처리"""
        request_info = self._prepare_request(url, param_name, payload, method)
        start_time = time.time()
        timeout_obj = aiohttp.ClientTimeout(total=self.timeout)

        try:
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                if method.upper() == "GET":
                    async with session.get(
                        request_info["url"],
                        headers=request_info["headers"]
                    ) as resp:
                        text = await resp.text()
                        status = resp.status
                else:
                    async with session.post(
                        request_info["url"],
                        json=request_info["data"],
                        headers=request_info["headers"]
                    ) as resp:
                        text = await resp.text()
                        status = resp.status

                # GET과 POST 모두에 대한 응답 반환
                return {
                    "request_info": request_info,
                    "status_code": status,
                    "_temp_response": text,
                    "response_time": round(time.time() - start_time, 4),
                    "payload_info": {**payload_info, "payload": payload}
                }

        except aiohttp.ClientError as error:
            return {
                "request_info": request_info,
                "status_code": -1,
                "_temp_response": f"{type(error).__name__}: {error}",
                "response_time": round(time.time() - start_time, 4),
                "payload_info": {**payload_info, "payload": payload}
            }

    async def send_payloads(self, url: str, param_name: str, method: str, payloads: list[dict]) -> list[dict]:        
        responses = []
        
        for payload_dict in payloads:
            try:
                if isinstance(payload_dict.get("payload"), list) and len(payload_dict["payload"]) == 2:
                    # 비교 페이로드 처리
                    pair_responses = []
                    response_lengths = []
                    
                    for payload in payload_dict["payload"]:
                        response_info = await self._submit_request(
                            url=url, 
                            param_name=param_name,
                            payload=payload,
                            method=method,
                            payload_info=payload_dict
                        )
                        pair_responses.append(response_info)
                        response_lengths.append(len(response_info["_temp_response"]))

                    # 응답 길이 비교
                    length_diff = abs(response_lengths[0] - response_lengths[1])
                    for response in pair_responses:
                        response["response_diff"] = {
                            "detected": length_diff > 0,
                            "pattern_type": "response_diff",
                            "evidence": f"Response length difference: {length_diff} characters",
                            "original_lengths": response_lengths
                        }
                    
                    responses.extend(pair_responses)
                else:
                    # 단일 페이로드 처리
                    if payload := payload_dict.get("payload"):
                        response_info = await self._submit_request(
                            url=url,
                            param_name=param_name,
                            payload=payload,
                            method=method,
                            payload_info=payload_dict
                        )
                        responses.append(response_info)
            except Exception as e:
                continue

        return responses

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
            return {}
        
    def analyze_res(self, response_info: dict) -> dict:
        try:
            # None 체크 추가
            if response_info is None:
                return None

            result = response_info.copy()
            response_text = result.pop('_temp_response', '')  

            # 취약점 분석 로직
            vulns = result.get("payload_info", {}).get("vulnerabilities", [])
            for vuln in vulns:
                vuln_type = vuln.get("type")
                
                if vuln_type == "sql_injection":
                    check_result = self.check_sqli(
                        response_text,
                        result.get("response_time", 0),
                        result.get("compare_data")
                    )
                    if check_result and check_result.get("detected"):
                        vuln.update(check_result)
                        
                elif vuln_type == "xss":
                    check_result = self.check_xss(
                        response_text,
                        result.get("payload_info", {}).get("payload", "")
                    )
                    if check_result and check_result.get("detected"):
                        vuln.update(check_result)
                        
                elif vuln_type == "ssti":
                    check_result = self.check_ssti(response_text)
                    if check_result and check_result.get("detected"):
                        vuln.update(check_result)
                        
            return result

        except Exception as e:
            return None

    def check_sqli(self, response: str, response_time: float, compare_data: dict = None) -> dict:
        # 1. SQL 에러 메시지 체크
        for dbms_type, dbms_info in self.sql_patterns.items():
            for pattern in dbms_info["patterns"]:
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

        # 3. DB 버전 정보 노출 체크 
        version_patterns = {
            'MySQL': r'MySQL server.*?version.*?(\d+\.\d+\.\d+)',
            'PostgreSQL': r'PostgreSQL.*?(\d+\.\d+)',
            'MSSQL': r'Microsoft SQL Server.*?(\d+\.\d+\.\d+)',
            'Oracle': r'Oracle Database.*?(\d+\.\d+\.\d+)',
            'SQLite': r'SQLite.*?(\d+\.\d+\.\d+)'
        }
  
        for dbms, pattern in version_patterns.items():
            if match := re.search(pattern, response, re.IGNORECASE):
                version_context = response[max(0, match.start()-50):min(len(response), match.end()+50)]
                return {
                    'detected': True,
                    'pattern_type': 'version_leak',
                    'evidence': (f'Database version leaked: {dbms} {match.group(1)}\n'
                            f'Context: {version_context}'),
                    'dbms': dbms,
                    'version': match.group(1)
                }

        # 4. True/False 응답 길이 차이 체크
        if compare_data and 'length' in compare_data:
            length_diff = abs(len(response) - compare_data['length'])
            if length_diff > 500:
                return {
                    'detected': True,
                    'pattern_type': 'response_diff',
                    'evidence': (f'Response length difference: {length_diff} characters\n'
                            f'Original length: {compare_data["length"]}\n'
                            f'New length: {len(response)}')
                }

    def check_xss(self, response_text: str, payload: str) -> dict:
        """XSS 취약점 체크 - 페이로드의 태그가 응답 본문에 그대로 있는지 확인"""
        
        # 페이로드에서 HTML 태그 추출 (내용 포함)
        tag_pattern = r'<([a-z0-9]+)[^>]*>([^<]*)</\1>'
        if tag_match := re.search(tag_pattern, payload, re.I):
            injected_tag = tag_match.group(0)  # 전체 태그 (예: <h1>test</h1>)
            
            if injected_tag in response_text:
                tag_pos = response_text.find(injected_tag)
                context = response_text[max(0, tag_pos-50):min(len(response_text), tag_pos+len(injected_tag)+50)]
                
                return {
                    'detected': True,
                    'pattern_type': 'html_injection',
                    'evidence': f'Injected HTML tag found: {injected_tag}',
                    'context': context
                }

    def check_ssti(self, response: str) -> dict:
    # 연산 결과 체크 
        if re.search(r'\b49\b', response):
            return {
                'detected': True,
                'pattern_type': 'calculation_result',
                'evidence': 'Template expression (7*7) was evaluated to 49'
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

class CommonPayloadHandler:
    def __init__(self, timeout: int = 10):
        self._sender = CommonPayloadSender(timeout=timeout)
        self._analyzer = ResponseAnalyzer()
        self._classifier = VulnerabilityClassifier()

    async def scan(self, url: str, param_name: str, param_type: str) -> Dict:
        try:
            print(f"Scanning URL: {url}, Parameter: {param_name}")
            
            responses = await self._sender.send_payloads(
                url=url,
                param_name=param_name,
                method=param_type,  # HTTP 메소드로 사용
                payloads=self._sender.common_payloads
            )
            
            if not responses:
                print("No responses received")
                return {
                    "param_name": param_name,
                    "scan_results": []
                }
            
            results = []
            for response in responses:
                analysis = self._analyzer.analyze_res(response)
                if analysis:
                    classified = self._classifier.classify_vuln(analysis)
                    if classified:
                        results.append(classified)

            return {
                "param_name": param_name,
                "scan_results": results
            }

        except Exception as e:
            print(f"Error in scan: {str(e)}")  # 디버깅용
            return {
                "param_name": param_name,
                "scan_results": []
            }