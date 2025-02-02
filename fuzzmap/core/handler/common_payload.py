import time
import gc
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
    payload: str
    response_text: str  # 분석 중에만 유지
    response_time: float
    response_length: Optional[int]
    vulnerabilities: List[VulnerabilityInfo]
    alert_triggered: bool = False
    alert_message: str = ""

    def cleanup(self):
        self.response_text = None


class CommonPayloadHandler:
    def __init__(self):
        self._payloads = Util.load_json(
            'handler/payloads/common_payload.json')['payloads']
        self._analyzer = ResponseAnalyzer(self._payloads)  # 페이로드 전달
        self._classifier = VulnerabilityClassifier()
        self.logger = Logger()

    async def scan(self, url: str, param_name: str,
                   param_info: Dict) -> List[ScanResult]:
        try:
            self.logger.info(
                f"Starting scan - URL: {url}, Parameter: {param_name}")
            method = param_info.get('method', 'GET')
            params = {param_name: ""}

            # 페이로드 분류
            clientside_payloads = []
            serverside_payloads = []

            for payload_info in self._payloads:
                try:
                    vuln_types = [
                        v['type'] for v in payload_info.get(
                            'vulnerabilities', [])]
                    payload = payload_info['payload']
                    payloads = [payload] if isinstance(
                        payload, str) else payload

                    if 'xss' in vuln_types:
                        clientside_payloads.extend(
                            [(p, payload_info) for p in payloads])
                    else:
                        serverside_payloads.extend(
                            [(p, payload_info) for p in payloads])
                except Exception as e:
                    self.logger.error(f"Error processing payload: {str(e)}")
                    continue

            self.logger.info(
                f"Payload classification completed - Client-side: {
                    len(clientside_payloads)}, Server-side: {
                    len(serverside_payloads)}")

            async def process_serverside():
                if not serverside_payloads:
                    return []
                try:
                    payloads_only = [p[0] for p in serverside_payloads]
                    self.logger.info(
                        f"Starting server-side scan with {len(payloads_only)} payloads")
                    responses = await RequestPayloadHandler.send_serverside(
                        url, params, method, payloads_only
                    )
                    results = []
                    for response, (_, payload_info) in zip(
                            responses, serverside_payloads):
                        result = ScanResult(
                            param_name=param_name,
                            payload=response.payload,
                            response_text=response.response_text,
                            response_time=response.response_time,
                            response_length=response.response_length,
                            vulnerabilities=[
                                VulnerabilityInfo(**vuln)
                                for vuln in payload_info.get('vulnerabilities', [])
                            ],
                            alert_triggered=False,
                            alert_message=""
                        )
                        analyzed_result = self._analyzer.analyze_res(result)
                        classified_result = self._classifier.classify_vuln(
                            analyzed_result)
                        result.cleanup()
                        results.append(classified_result)
                    return results
                except Exception as e:
                    self.logger.error(f"Server-side scan failed: {str(e)}")
                    return []

            async def process_clientside():
                if not clientside_payloads:
                    return []
                try:
                    payloads_only = [p[0] for p in clientside_payloads]
                    self.logger.info(
                        f"Starting client-side scan with {len(payloads_only)} payloads")
                    responses = await RequestPayloadHandler.send_clientside(
                        url, params, method, payloads_only
                    )
                    results = []
                    for response, (_, payload_info) in zip(
                            responses, clientside_payloads):
                        result = ScanResult(
                            param_name=param_name,
                            payload=response.payload,
                            response_text=response.response_text,
                            response_time=response.response_time,
                            response_length=response.response_length,
                            vulnerabilities=[
                                VulnerabilityInfo(**vuln)
                                for vuln in payload_info.get('vulnerabilities', [])
                            ],
                            alert_triggered=getattr(
                                response, 'alert_triggered', False),
                            alert_message=getattr(
                                response, 'alert_message', '')
                        )
                        analyzed_result = self._analyzer.analyze_res(result)
                        classified_result = self._classifier.classify_vuln(
                            analyzed_result)
                        result.cleanup()
                        results.append(classified_result)
                    return results
                except Exception as e:
                    self.logger.error(f"Client-side scan failed: {str(e)}")
                    return []

            # server-side와 client-side 요청을 병렬로 실행
            serverside_results, clientside_results = await asyncio.gather(
                process_serverside(),
                process_clientside()
            )

            total_results = serverside_results + clientside_results
            self.logger.info(
                f"Scan completed - Total results: {len(total_results)}")
            return total_results

        except Exception as e:
            self.logger.error(f"Scan failed with error: {str(e)}")
            return []


class ResponseAnalyzer:
    def __init__(self, payloads=None):
        # XSS 관련 정규식 패턴 컴파일
        self.tag_pattern = re.compile(r'<([a-z0-9]+)[^>]*>([^<]*)</\1>', re.I)
        self.partial_pattern = re.compile(r'<[^>]*>', re.I)

        # SSTI 관련 정규식 패턴 컴파일
        self.ssti_pattern = re.compile(r'\b1879080904\b')

        # SQL 에러 패턴 컴파일
        self.sql_patterns = self._compile_sql_patterns()
        self._payloads = payloads if payloads else []

        # Boolean pairs 로드 추가
        self.boolean_pairs = []
        self.boolean_responses = {}  # 페이로드 쌍의 응답 저장할 딕셔너리
        if self._payloads:
            self._load_boolean_payloads()

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

    def _load_boolean_payloads(self):
        """common_payload.json에서 boolean 페이로드 쌍 추출"""
        self.boolean_pairs = []
        self.pair_responses = {}

        for entry in self._payloads:
            if isinstance(entry.get('payload'), list) and len(
                    entry['payload']) == 2:
                self.boolean_pairs.append(entry)
                self.pair_responses[tuple(entry['payload'])] = {}

    def analyze_res(self, scan_result: ScanResult) -> ScanResult:
        response_diff = None

        # Boolean pair 확인 및 response_diff 계산
        for pair in self.boolean_pairs:
            pair_key = tuple(pair['payload'])
            if scan_result.payload in pair_key:
                # 현재 응답 길이 저장
                self.pair_responses[pair_key][scan_result.payload] = len(
                    scan_result.response_text)

                # 페어의 두 응답이 모두 있으면 차이 계산
                if len(self.pair_responses[pair_key]) == 2:
                    response_diff = abs(
                        self.pair_responses[pair_key][pair_key[0]] -
                        self.pair_responses[pair_key][pair_key[1]]
                    )

        # 취약점 검사 및 결과 업데이트
        for vuln in scan_result.vulnerabilities:
            detection = None
            if vuln.type == "sql_injection":
                detection = self.check_sqli(
                    scan_result.response_text,
                    scan_result.response_time,
                    response_diff)
            elif vuln.type == "xss":
                detection = self.check_xss(
                    scan_result.response_text,
                    scan_result.payload,
                    scan_result.alert_triggered)
            elif vuln.type == "ssti":
                detection = self.check_ssti(
                    scan_result.response_text, scan_result.alert_message)

            if detection:  # detection False여도 반환
                vuln.detected = detection.detected
                vuln.pattern_type = detection.pattern_type
                vuln.evidence = detection.evidence
                vuln.context = detection.context
                vuln.encoding_info = detection.encoding_info
                vuln.response_diff = detection.response_diff  # response_diff 추가

        return scan_result

    def check_sqli(self, response: str, response_time: float,
                   response_diff: Optional[int] = None) -> VulnerabilityInfo:
        # SQL 에러 메시지 체크
        for dbms_type, dbms_info in self.sql_patterns.items():
            for pattern in dbms_info["patterns"]:
                if match := pattern.search(response):
                    context = self._get_context(response, match.group(0))
                    return VulnerabilityInfo(
                        type="sql_injection",
                        pattern_type="error",
                        evidence=f"SQL error detected ({dbms_type})",
                        context=context,
                        detected=True,
                        response_diff=response_diff
                    )

        if response_time > 5:
            return VulnerabilityInfo(
                type="sql_injection",
                pattern_type="time_delay",
                evidence=f"Response delayed {response_time:.2f}s",
                detected=True,
                response_diff=response_diff
            )

        if response_diff and response_diff > 500:
            return VulnerabilityInfo(
                type="sql_injection",
                pattern_type="boolean",
                evidence=f"Response length difference {response_diff} bytes",
                detected=True,
                response_diff=response_diff
            )

        return VulnerabilityInfo(
            type="sql_injection",
            detected=False,
            response_diff=response_diff)

    def check_xss(self, response_text: str, payload: str,
                  alert_triggered: bool = False) -> VulnerabilityInfo:
        if alert_triggered:
            return VulnerabilityInfo(
                type="xss",
                pattern_type="alert_triggered",
                evidence="JavaScript alert triggered",
                detected=True
            )

        if isinstance(payload, list):
            payload = payload[0]

        # URL 인코딩 체크
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

        # HTML 인코딩 체크
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

        # tag 체크
        if tag_match := self.tag_pattern.search(decoded_payload):
            injected_tag = tag_match.group(0)
            if injected_tag in response_text:
                context = self._get_context(response_text, injected_tag)

                # HTML 인코딩 상태만 체크
                encoding_status = []
                for char, encoded in html_encoded_chars.items():
                    if char in injected_tag:
                        if encoded in context:
                            encoding_status.append(f"{char} is HTML encoded")
                        else:
                            encoding_status.append(f"{char} is unfiltered")

                return VulnerabilityInfo(
                    type="xss",
                    pattern_type="html_injection" if not is_url_encoded else "url_encoded",
                    evidence=f"HTML tag injected {injected_tag}",
                    context=context,
                    detected=True,
                    encoding_info=' | '.join(
                        encoding_status) if encoding_status else None
                )

        # reflected 체크
        if decoded_payload in response_text:
            context = self._get_context(response_text, decoded_payload)
            return VulnerabilityInfo(
                type="xss",
                pattern_type="reflected",
                evidence=f"Payload reflected: {decoded_payload}",
                context=context,
                detected=True
            )

        # partial tag 체크
        if injected_partial := self.partial_pattern.search(decoded_payload):
            partial_tag = injected_partial.group(0)
            if partial_tag in response_text:
                context = self._get_context(response_text, partial_tag)
                return VulnerabilityInfo(
                    type="xss",
                    pattern_type="partial_tag_injection",
                    evidence=f"Partial HTML tag injected {partial_tag}",
                    context=context,
                    detected=True
                )

        return VulnerabilityInfo(type="xss", detected=False)

    def check_ssti(
            self,
            response_text: str,
            alert_message: str = None) -> VulnerabilityInfo:
        if alert_message and '1879080904' in alert_message:
            return VulnerabilityInfo(
                type="ssti",
                pattern_type="calculation_result",
                evidence="Template expression (1234**3) evaluated in alert",
                detected=True
            )

        if match := self.ssti_pattern.search(response_text):
            context = response_text[max(
                0, match.start() - 50):min(len(response_text), match.end() + 50)]
            return VulnerabilityInfo(
                type="ssti",
                pattern_type="calculation_result",
                evidence="Template expression (1234**3) evaluated",
                context=context,
                detected=True
            )
        return VulnerabilityInfo(type="ssti", detected=False)

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


"""테스트"""
if __name__ == "__main__":
    async def test():
        test_url = "http://php.testinvicti.com/artist.php"
        test_param = {
            "name": "id",
            "value": "",
            "method": "GET"
        }

        try:
            start_time = time.time()
            common_handler = CommonPayloadHandler()
            results = await common_handler.scan(
                url=test_url,
                param_name=test_param["name"],
                param_info=test_param
            )
            print(f"실행 시간: {time.time() - start_time:.2f} 초")
            print(f"찾은 결과 수: {len(results)}")
            print("\n[+] Scan Results:")

            i = 0
            while i < len(results):
                result = results[i]
                result2 = results[i + 1] if i + 1 < len(results) else None

                is_boolean_pair = result2 and any(
                    isinstance(p.get('payload'), list) and
                    result.payload in p['payload'] and
                    result2.payload in p['payload']
                    for p in common_handler._payloads)

                print("===")
                print(f"Param_Name: {result.param_name}")

                if is_boolean_pair:
                    print(f"Payload: {result.payload} , {result2.payload}")
                    print(
                        f"Response_Time: {
                            result.response_time:.2f}s, {
                            result2.response_time:.2f}s")
                    print(
                        f"Response_Length: {
                            result.response_length}, {
                            result2.response_length}")

                    for vuln in result2.vulnerabilities:
                        print("---")
                        print(f"Type: {vuln.type}")
                        print(f"Pattern_Type: {vuln.pattern_type}")
                        print(f"Confidence: {vuln.confidence}%")
                        print(f"Evidence: {vuln.evidence}")
                        if vuln.response_diff:
                            print(f"Response_Diff: {vuln.response_diff}")
                        if vuln.encoding_info:
                            print(f"Encoding: {vuln.encoding_info}")
                    i += 2
                else:
                    print(f"Payload: {result.payload}")
                    print(f"Response_Time: {result.response_time:.2f}s")

                    for vuln in result.vulnerabilities:
                        print("---")
                        print(f"Type: {vuln.type}")
                        print(f"Pattern_Type: {vuln.pattern_type}")
                        print(f"Confidence: {vuln.confidence}%")
                        print(f"Evidence: {vuln.evidence}")
                        if vuln.response_diff:
                            print(f"Response_Diff: {vuln.response_diff}")
                        if vuln.encoding_info:
                            print(f"Encoding: {vuln.encoding_info}")
                    i += 1
                print()

        except Exception as e:
            print(f"Error: {e}")

    asyncio.run(test())
