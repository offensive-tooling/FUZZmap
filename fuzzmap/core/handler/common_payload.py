import time
import re
import asyncio
from typing import Dict, List, Optional

from fuzzmap.core.util.util import Util
from fuzzmap.core.logging.log import Logger
from fuzzmap.core.handler.request_payload import RequestPayloadHandler

from dataclasses import dataclass


@dataclass
class VulnerabilityInfo:
    type: str
    pattern_type: Optional[str] = None
    evidence: Optional[str] = None
    confidence: Optional[int] = 0
    context: Optional[str] = None
    detected: bool = False
    encoding_info: Optional[str] = None
    response_diff: Optional[int] = None


@dataclass
class ScanResult:
    param_name: str
    payload: str | List[str]
    response_text: str | List[str]
    response_time: float | List[float]
    response_length: int | List[int]
    vulnerabilities: List[VulnerabilityInfo]
    dialog_triggered: bool = False
    dialog_type: Optional[str] = None
    dialog_message: str = ""

    def cleanup(self):
        self.response_text = None


class CommonPayloadHandler:
    def __init__(self):
        self._payloads = Util.load_json('handler/payloads/common_payload.json')['payloads']
        self._analyzer = ResponseAnalyzer(self._payloads)
        self._classifier = VulnerabilityClassifier()
        self.logger = Logger()
        # 클라이언트사이드 스캔 취약점 타입
        self.CLIENTSIDE_VULN_TYPES = {'xss'}

    async def scan(self, url: str, params: Dict[str, str], method: str = "GET", 
                  user_agent: Optional[str] = None, cookies: Optional[Dict[str, str]] = None):
        try:
            self.logger.info(f"Starting scan - URL: {url}, Parameters: {list(params.keys())}")
            
            empty_params = {k: v for k, v in params.items() if not v}
            if not empty_params:
                self.logger.info("No empty parameters to test")
                return []

            clientside_payloads = [(p['payload'], p) for p in self._payloads
                                 if any(v['type'] in self.CLIENTSIDE_VULN_TYPES 
                                      for v in p.get('vulnerabilities', []))]

            serverside_payloads = [(p['payload'], p) for p in self._payloads
                                 if not any(v['type'] in self.CLIENTSIDE_VULN_TYPES 
                                          for v in p.get('vulnerabilities', []))]

            # 클라이언트사이드와 서버사이드 테스트를 동시에 실행
            client_results, server_results = await asyncio.gather(
                self._process_clientside(url, params, clientside_payloads, method, empty_params, user_agent, cookies),
                self._process_serverside(url, params, serverside_payloads, method, empty_params, user_agent, cookies)
            )

            # 취약점이 발견된 결과만 필터링
            all_results = []
            for result in (client_results + server_results):
                if any(vuln.detected for vuln in result.vulnerabilities):
                    all_results.append(result)

            self.logger.info(f"Scan completed - Found vulnerabilities: {len(all_results)}")
            return all_results

        except Exception as e:
            self.logger.error(f"Scan failed with error: {str(e)}")
            return []

    async def _test_parameter(self, url: str, params: Dict[str, str],
                            clientside_payloads: List, serverside_payloads: List,
                            method: str, target_param: str, 
                            user_agent: Optional[str] = None, cookies: Optional[Dict[str, str]] = None) -> List[ScanResult]:
        """단일 파라미터에 대한 모든 테스트"""
        try:
            # 클라이언트사이드와 서버사이드 테스트를 동시에 실행
            client_results, server_results = await asyncio.gather(
                self._process_clientside(url, params, clientside_payloads, method, target_param, user_agent, cookies),
                self._process_serverside(url, params, serverside_payloads, method, target_param, user_agent, cookies)
            )
            return client_results + server_results
        except Exception as e:
            self.logger.error(f"Test for parameter '{target_param}' failed: {e}")
            raise

    async def _process_serverside(self, url: str, params: Dict[str, str],
                                serverside_payloads: List, method: str,
                                current_param: str,
                                user_agent: Optional[str] = None, cookies: Optional[Dict[str, str]] = None) -> List[ScanResult]:
        try:
            payloads_only = self._process_payloads(serverside_payloads)

            responses = await RequestPayloadHandler.send_serverside(
                url=url,
                params=params,
                method=method,
                payloads=payloads_only,
                user_agent=user_agent,
                cookies=cookies
            )

            results = []
            current_index = 0
            for payload, payload_info in serverside_payloads:
                response_slice = responses[current_index:current_index +
                                        (len(payload) if isinstance(payload, list) else 1)]
                
                result = ScanResult(
                    param_name=current_param,
                    payload=payload,
                    response_text=self._process_response(response_slice, payload, 'response_text'),
                    response_time=self._process_response(response_slice, payload, 'response_time'),
                    response_length=self._process_response(response_slice, payload, 'response_length'),
                    vulnerabilities=[VulnerabilityInfo(**vuln) 
                                   for vuln in payload_info.get('vulnerabilities', [])]
                )

                analyzed_result = self._analyzer.analyze_res(result, payload_info)
                classified_result = self._classifier.classify_vuln(analyzed_result)
                result.cleanup()
                results.append(classified_result)

                current_index += len(payload) if isinstance(payload, list) else 1

            return results
        except Exception as e:
            self.logger.error(f"Server-side scan failed: {str(e)}")
            return []

    async def _process_clientside(self, url: str, params: Dict[str, str],
                                clientside_payloads: List, method: str,
                                current_param: str,
                                user_agent: Optional[str] = None, cookies: Optional[Dict[str, str]] = None) -> List[ScanResult]:
        try:
            payloads_only = self._process_payloads(clientside_payloads)

            responses = await RequestPayloadHandler.send_clientside(
                url=url,
                params=params,
                method=method,
                payloads=payloads_only,
                user_agent=user_agent,
                cookies=cookies
            )

            results = []
            current_index = 0
            for payload, payload_info in clientside_payloads:
                response_slice = responses[current_index:current_index +
                                        (len(payload) if isinstance(payload, list) else 1)]
                
                result = ScanResult(
                    param_name=current_param,
                    payload=payload,
                    response_text=self._process_response(response_slice, payload, 'response_text'),
                    response_time=self._process_response(response_slice, payload, 'response_time'),
                    response_length=self._process_response(response_slice, payload, 'response_length'),
                    vulnerabilities=[VulnerabilityInfo(**vuln) 
                                   for vuln in payload_info.get('vulnerabilities', [])],
                    dialog_triggered=any(r.dialog_triggered for r in response_slice),
                    dialog_type=next((r.dialog_type for r in response_slice if r.dialog_triggered), None),
                    dialog_message="; ".join(filter(None, [r.dialog_message for r in response_slice if r.dialog_triggered]))
                )

                analyzed_result = self._analyzer.analyze_res(result, payload_info)
                classified_result = self._classifier.classify_vuln(analyzed_result)
                result.cleanup()
                results.append(classified_result)

                current_index += len(payload) if isinstance(payload, list) else 1

            return results
        except Exception as e:
            self.logger.error(f"Client-side scan failed: {str(e)}")
            return []

    def _process_payloads(self, payloads: List[tuple]) -> List[str]:
        """페이로드 리스트 처리를 위한 공통 메서드"""
        payloads_only = []
        for payload, _ in payloads:
            if isinstance(payload, list):
                payloads_only.extend(payload)
            else:
                payloads_only.append(payload)
        return payloads_only

    def _process_response(self, response_slice, payload, field: str):
        """응답 데이터 처리를 위한 공통 메서드"""
        data = [getattr(r, field) for r in response_slice]
        return data if isinstance(payload, list) else data[0]


class ResponseAnalyzer:
    def __init__(self, payloads=None):
        # XSS 정규식 패턴 컴파일
        self.tag_pattern = re.compile(
            r'<[^>]+>.*?</[^>]+>|<[^<>]+>',
            re.I | re.DOTALL)

        # SSTI 정규식 패턴 컴파일
        self.ssti_pattern = re.compile(r'\b1879080904\b')

        # SQL 에러 패턴 컴파일
        self.sql_patterns = self._compile_sql_patterns()

    def _compile_sql_patterns(self):
        """SQL 에러 패턴 컴파일해서 저장"""
        raw_patterns = Util.load_json('handler/config/sql_error.json')
        compiled_patterns = {}

        for dbms_type, dbms_info in raw_patterns.items():
            patterns = dbms_info.get("patterns", [])
            compiled_patterns[dbms_type] = {
                "patterns": [
                    re.compile(
                        pattern,
                        re.IGNORECASE) for pattern in patterns]}
        return compiled_patterns

    def analyze_res(self, scan_result: ScanResult, payload_info: dict = None) -> ScanResult:
        response_diff = None
        if isinstance(scan_result.response_length, list) and len(
                scan_result.response_length) >= 2:
            response_diff = abs(
                scan_result.response_length[0] -
                scan_result.response_length[1])

        new_vulnerabilities = []
        for vuln in scan_result.vulnerabilities:
            if vuln.type == "sql_injection":
                detections = self.check_sqli(
                    scan_result.response_text,
                    scan_result.response_time,
                    response_diff,
                    payload_info)
                new_vulnerabilities.extend(detections)
            elif vuln.type == "xss":
                detections = self.check_xss(
                    scan_result.response_text,
                    scan_result.payload,
                    scan_result.dialog_triggered)
                new_vulnerabilities.extend(detections)
            elif vuln.type == "ssti":
                detections = self.check_ssti(
                    scan_result.response_text, scan_result.dialog_message)
                new_vulnerabilities.extend(detections)

        scan_result.vulnerabilities = new_vulnerabilities
        return scan_result

    def check_sqli(self, response, response_time, response_diff, payload_info: dict = None) -> List[VulnerabilityInfo]:
        vulnerabilities = []
        
        # error-based 체크
        responses_to_check = response if isinstance(response, list) else [response]
        for r in responses_to_check:
            found_error = False  # 각 DBMS 타입별로 첫 번째 매칭만 사용
            for dbms_type, dbms_info in self.sql_patterns.items():
                if found_error:  # 이미 에러를 찾았다면 다음 응답으로 넘어감 
                    break
                for pattern in dbms_info["patterns"]:
                    if match := pattern.search(str(r)):
                        context = self._get_context(str(r), match.group(0))
                        vulnerabilities.append(VulnerabilityInfo(
                            type="sql_injection",
                            pattern_type="error",
                            evidence=f"SQL error detected ({dbms_type})",
                            context=context,
                            detected=True
                        ))
                        found_error = True
                        break

        # time-based 체크 - description에 "time-based"가 있는 경우만 체크
        if payload_info and 'description' in payload_info and 'time-based' in payload_info['description'].lower():
            times_to_check = response_time if isinstance(response_time, list) else [response_time]
            for time in times_to_check:
                if time > 5:
                    vulnerabilities.append(VulnerabilityInfo(
                        type="sql_injection",
                        pattern_type="time_delay",
                        evidence=f"Response delayed {time:.2f}s",
                        detected=True
                    ))

        # boolean-based 체크
        if response_diff and response_diff > 500:
            vulnerabilities.append(VulnerabilityInfo(
                type="sql_injection",
                pattern_type="boolean",
                evidence=f"Response length difference {response_diff} bytes",
                detected=True,
                response_diff=response_diff
            ))

        return vulnerabilities if vulnerabilities else [
            VulnerabilityInfo(type="sql_injection", detected=False)]

    def check_xss(self, response_text: str, payload: str,
                  dialog_triggered: bool = False) -> List[VulnerabilityInfo]:
        vulnerabilities = []

        if dialog_triggered:
            vulnerabilities.append(VulnerabilityInfo(
                type="xss",
                pattern_type="dialog_triggered",
                evidence="JavaScript dialog triggered",
                detected=True
            ))

        if isinstance(payload, list):
            payload = payload[0]

        url_encoded_chars = {
            '%3C': '<',
            '%3E': '>',
            '%22': '"',
            '%27': "'",
            '%20': ' ',
            '%3D': '=',
            '%28': '(',
            '%29': ')'
        }

        html_encoded_chars = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;',
            '(': '&#40;',
            ')': '&#41;',
            '=': '&#61;',
            ' ': '&nbsp;'
        }

        is_url_encoded = any(
            encoded in payload for encoded in url_encoded_chars)
        decoded_payload = payload
        for encoded, char in url_encoded_chars.items():
            decoded_payload = decoded_payload.replace(encoded, char)

        # HTML Injection 체크
        if tag_match := self.tag_pattern.search(decoded_payload):
            injected_tag = tag_match.group(0)
            if injected_tag in response_text:
                context = self._get_context(response_text, injected_tag)

                encoding_status = [
                    f"{char} is {'HTML encoded' if encoded in context else 'unfiltered'}"
                    for char, encoded in html_encoded_chars.items()
                    if char in injected_tag
                ]

                vulnerabilities.append(VulnerabilityInfo(
                    type="xss",
                    pattern_type="html_injection",
                    evidence=f"HTML tag injected {injected_tag} {'(url encoded)' if is_url_encoded else ''}",
                    context=context,
                    detected=True,
                    encoding_info=' | '.join(
                        encoding_status) if encoding_status else None
                ))

        # Reflected 체크
        if decoded_payload in response_text:
            context = self._get_context(response_text, decoded_payload)
            vulnerabilities.append(VulnerabilityInfo(
                type="xss",
                pattern_type="reflected",
                evidence=f"Payload reflected: {decoded_payload}",
                context=context,
                detected=True
            ))

        return vulnerabilities if vulnerabilities else [
            VulnerabilityInfo(type="xss", detected=False)]

    def check_ssti(self, response_text: str,
                   dialog_message: str = None) -> List[VulnerabilityInfo]:
        if self.ssti_pattern.pattern in (dialog_message or '') or self.ssti_pattern.search(response_text):
            context = self._get_context(
                response_text, self.ssti_pattern.pattern) if self.ssti_pattern.pattern in response_text else None
            return [VulnerabilityInfo(
                type="ssti",
                pattern_type="calculation_result",
                evidence="Template expression (1234**3) evaluated",
                context=context,
                detected=True
            )]

        return [VulnerabilityInfo(type="ssti", detected=False)]

    def _get_context(self, text: str, pattern: str, window: int = 50) -> str:
        pos = text.find(pattern)
        return text[max(0, pos - window):min(len(text),
                                             pos + len(pattern) + window)]


class VulnerabilityClassifier:
    def __init__(self):
        self.confidence_scores = Util.load_json(
            'handler/config/vuln_confidence.json')

    def classify_vuln(self, scan_result: ScanResult) -> ScanResult:
        for vuln in scan_result.vulnerabilities:
            if vuln.detected:
                vuln.confidence = self.calc_confidence(
                    vuln.type, vuln.pattern_type)
        return scan_result

    def calc_confidence(self, vuln_type: str, pattern_type: str) -> int:
        if not vuln_type or not pattern_type:
            return 0
        return self.confidence_scores.get(vuln_type, {}).get(pattern_type, 0)
