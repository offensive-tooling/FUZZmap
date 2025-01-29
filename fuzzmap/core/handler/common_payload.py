import gc
import re
import asyncio
from typing import Dict, List, Optional

from fuzzmap.core.util.util import Util
from fuzzmap.core.logging.log import Logger
from fuzzmap.core.handler.payload_request import RequestPayloadHandler

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
        gc.collect()


class CommonPayloadHandler:
    def __init__(self):
        self._payloads = Util.load_json(
            'handler/payloads/common_payload.json')['payloads']
        self._analyzer = ResponseAnalyzer(self._payloads)
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
                            alert_triggered=getattr(response, 'alert_triggered', False),
                            alert_message=getattr(response, 'alert_message', '')
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

    def analyze_res(self, scan_result: ScanResult) -> ScanResult:
        # Original payload 확인 및 response_diff 계산
        original_payload = next(
            (p for p in self._payloads if scan_result.payload in p.get(
                'payload', [])), None)

        response_diff = (
            abs(len(scan_result.response_text[0]) - len(scan_result.response_text[1]))
            if original_payload
            and isinstance(original_payload.get('payload'), list)
            and isinstance(scan_result.response_text, list)
            and len(scan_result.response_text) == 2
            else None
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

            if detection and detection.detected:
                vuln.detected = detection.detected
                vuln.pattern_type = detection.pattern_type
                vuln.evidence = detection.evidence
                vuln.context = detection.context
                vuln.encoding_info = detection.encoding_info

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
                        detected=True
                    )

        if response_time > 5:
            return VulnerabilityInfo(
                type="sql_injection",
                pattern_type="time_delay",
                evidence=f"Response delayed {response_time:.2f}s",
                detected=True
            )

        if response_diff and response_diff > 500:
            return VulnerabilityInfo(
                type="sql_injection",
                pattern_type="boolean",
                evidence=f"Response length difference {response_diff} bytes",
                detected=True,
                response_diff=response_diff
            )

        return VulnerabilityInfo(type="sql_injection", detected=False)

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

        if tag_match := self.tag_pattern.search(payload):
            injected_tag = tag_match.group(0)
            if injected_tag in response_text:
                context = self._get_context(response_text, injected_tag)
                special_chars = {
                    '<': '&lt;',
                    '>': '&gt;',
                    '"': '&quot;',
                    "'": '&#x27;'}
                encoding_status = []
                for char, encoded in special_chars.items():
                    if char in injected_tag:
                        if encoded in context:
                            encoding_status.append(f"{char} is HTML encoded")
                        else:
                            encoding_status.append(f"{char} is unencoded")

                return VulnerabilityInfo(
                    type="xss",
                    pattern_type="html_injection",
                    evidence=f"HTML tag injected {injected_tag}",
                    context=context,
                    detected=True,
                    encoding_info=' | '.join(encoding_status) if encoding_status else None)

        if injected_partial := self.partial_pattern.search(payload):
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
import time
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

            end_time = time.time()
            execution_time = end_time - start_time

            print(f"실행 시간: {execution_time:.2f} 초")
            print(f"찾은 결과 수: {len(results)}")

            print("\n[+] Scan Results:")
            for result in results:
                print("===")
                print(f"Param_Name: {result.param_name}")
                print(f"Payload: {result.payload}")
                print(f"Response_Time: {result.response_time:.2f}s")
                print(f"Alert_Triggered: {result.alert_triggered}")
                print(f"Alert_Message: {result.alert_message}")

                for vuln in result.vulnerabilities:
                    print(f"Type: {vuln.type}")
                    print(f"Pattern_Type: {vuln.pattern_type}")
                    print(f"Confidence: {vuln.confidence}%")
                    print(f"Evidence: {vuln.evidence}")
                    if vuln.encoding_info:
                        print(f"Encoding: {vuln.encoding_info}")
                    print("---")
                print()
        except Exception as e:
            print(f"Error: {e}")

    asyncio.run(test())
