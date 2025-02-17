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
    payload: str | List[str]
    response_text: str | List[str]
    response_time: float | List[float]
    response_length: int | List[int]
    vulnerabilities: List[VulnerabilityInfo]
    alert_triggered: bool = False
    alert_message: str = ""

    def cleanup(self):
        self.response_text = None


class CommonPayloadHandler:
    def __init__(self):
        self._payloads = Util.load_json(
            'handler/payloads/common_payload.json')['payloads']
        self._analyzer = ResponseAnalyzer(self._payloads)
        self._classifier = VulnerabilityClassifier()
        self.logger = Logger()

    async def scan(
            self, url: str, params: Dict[str, str], method: str = "GET"):
        try:
            self.logger.info(
                f"Starting scan - URL: {url}, Parameters: {list(params.keys())}")

            # XSS 취약점만 clientside 스캔
            clientside_payloads = [(p['payload'], p) for p in self._payloads
                                   if any(v['type'] == 'xss' for v in p.get('vulnerabilities', []))]

            serverside_payloads = [(p['payload'], p) for p in self._payloads
                                   if not any(v['type'] == 'xss' for v in p.get('vulnerabilities', []))]

            empty_params = [k for k, v in params.items() if v == ""]
            total_results = []

            for param_name in empty_params:
                test_param = {param_name: ""}

                client_results, server_results = await asyncio.gather(
                    self._process_clientside(
                        url, test_param, clientside_payloads, method),
                    self._process_serverside(
                        url, test_param, serverside_payloads, method)
                )

                total_results.extend(client_results + server_results)

            self.logger.info(
                f"Scan completed - Total results: {len(total_results)}")
            return total_results

        except Exception as e:
            self.logger.error(f"Scan failed with error: {str(e)}")
            return []

    async def _process_serverside(self, url: str, test_param: Dict[str, str],
                                  serverside_payloads: List, method: str) -> List[ScanResult]:
        try:
            payloads_only = []
            for payload, _ in serverside_payloads:
                if isinstance(payload, list):
                    payloads_only.extend(payload)
                else:
                    payloads_only.append(payload)

            responses = await RequestPayloadHandler.send_serverside(
                url=url,
                params=test_param,
                method=method,
                payloads=payloads_only
            )

            results = []
            current_index = 0
            for payload, payload_info in serverside_payloads:
                response_slice = responses[current_index:current_index +
                                           (len(payload) if isinstance(payload, list) else 1)]

                result = ScanResult(
                    param_name=list(test_param.keys())[0],
                    payload=payload,
                    response_text=[r.response_text for r in response_slice] if isinstance(
                        payload, list) else response_slice[0].response_text,
                    response_time=[r.response_time for r in response_slice] if isinstance(
                        payload, list) else response_slice[0].response_time,
                    response_length=[r.response_length for r in response_slice] if isinstance(
                        payload, list) else response_slice[0].response_length,
                    vulnerabilities=[VulnerabilityInfo(
                        **vuln) for vuln in payload_info.get('vulnerabilities', [])]
                )

                analyzed_result = self._analyzer.analyze_res(result)
                classified_result = self._classifier.classify_vuln(
                    analyzed_result)
                result.cleanup()
                results.append(classified_result)

                current_index += len(payload) if isinstance(payload,
                                                            list) else 1

            return results
        except Exception as e:
            self.logger.error(f"Server-side scan failed: {str(e)}")
            return []

    async def _process_clientside(self, url: str, test_param: Dict[str, str],
                                  clientside_payloads: List, method: str) -> List[ScanResult]:
        try:
            payloads_only = []
            for payload, _ in clientside_payloads:
                if isinstance(payload, list):
                    payloads_only.extend(payload)
                else:
                    payloads_only.append(payload)

            responses = await RequestPayloadHandler.send_clientside(
                url=url,
                params=test_param,
                method=method,
                payloads=payloads_only
            )

            results = []
            current_index = 0
            for payload, payload_info in clientside_payloads:
                response_slice = responses[current_index:current_index +
                                           (len(payload) if isinstance(payload, list) else 1)]

                result = ScanResult(
                    param_name=list(test_param.keys())[0],
                    payload=payload,
                    response_text=[r.response_text for r in response_slice] if isinstance(
                        payload, list) else response_slice[0].response_text,
                    response_time=[r.response_time for r in response_slice] if isinstance(
                        payload, list) else response_slice[0].response_time,
                    response_length=[r.response_length for r in response_slice] if isinstance(
                        payload, list) else response_slice[0].response_length,
                    vulnerabilities=[VulnerabilityInfo(
                        **vuln) for vuln in payload_info.get('vulnerabilities', [])],
                    alert_triggered=any(
                        r.alert_triggered for r in response_slice),
                    alert_message="; ".join(
                        filter(None, [r.alert_message for r in response_slice]))
                )

                analyzed_result = self._analyzer.analyze_res(result)
                classified_result = self._classifier.classify_vuln(
                    analyzed_result)
                result.cleanup()
                results.append(classified_result)

                current_index += len(payload) if isinstance(payload,
                                                            list) else 1

            return results
        except Exception as e:
            self.logger.error(f"Client-side scan failed: {str(e)}")
            return []


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

    def analyze_res(self, scan_result: ScanResult) -> ScanResult:
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
                    response_diff)
                new_vulnerabilities.extend(detections)
            elif vuln.type == "xss":
                detections = self.check_xss(
                    scan_result.response_text,
                    scan_result.payload,
                    scan_result.alert_triggered)
                new_vulnerabilities.extend(detections)
            elif vuln.type == "ssti":
                detections = self.check_ssti(
                    scan_result.response_text, scan_result.alert_message)
                new_vulnerabilities.extend(detections)

        scan_result.vulnerabilities = new_vulnerabilities
        return scan_result

    def check_sqli(self, response, response_time, response_diff):
        vulnerabilities = []

        # error-based 체크
        if isinstance(response, list):
            for r in response:
                for dbms_type, dbms_info in self.sql_patterns.items():
                    for pattern in dbms_info["patterns"]:
                        if match := pattern.search(r):
                            context = self._get_context(r, match.group(0))
                            vulnerabilities.append(VulnerabilityInfo(
                                type="sql_injection",
                                pattern_type="error",
                                evidence=f"SQL error detected ({dbms_type})",
                                context=context,
                                detected=True
                            ))

        # time-based 체크
        if isinstance(response_time, list):
            for time in response_time:
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
                  alert_triggered: bool = False) -> List[VulnerabilityInfo]:
        vulnerabilities = []

        if alert_triggered:
            vulnerabilities.append(VulnerabilityInfo(
                type="xss",
                pattern_type="alert_triggered",
                evidence="JavaScript alert triggered",
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
                    f"{char} is {
                        'HTML encoded' if encoded in context else 'unfiltered'}"
                    for char, encoded in html_encoded_chars.items()
                    if char in injected_tag
                ]

                vulnerabilities.append(VulnerabilityInfo(
                    type="xss",
                    pattern_type="html_injection",
                    evidence=f"HTML tag injected {injected_tag} {
                        '(url encoded)' if is_url_encoded else ''}",
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
                   alert_message: str = None) -> List[VulnerabilityInfo]:
        if '1879080904' in (
                alert_message or '') or self.ssti_pattern.search(response_text):
            context = self._get_context(
                response_text, '1879080904') if '1879080904' in response_text else None
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


"""테스트"""
if __name__ == "__main__":
    async def test():
        test_url = "http://php.testinvicti.com/artist.php"
        params = {
            "id": "",
            "user": "admin"  # 고정값 파라미터는 스캔 생략
        }
        try:
            start_time = time.time()
            common_handler = CommonPayloadHandler()
            results = await common_handler.scan(url=test_url, params=params, method="GET")

            print(f"\n[+] Scan Results:")
            for result in results:
                # 기본 정보 출력
                print(f"\nParameter: {result.param_name}")
                print(
                    f"Payload{
                        's' if isinstance(
                            result.payload,
                            list) else ''}: {
                        result.payload}")
                print(
                    f"Response Time{
                        's' if isinstance(
                            result.response_time,
                            list) else ''}: {
                        result.response_time}")
                print(
                    f"Response Length{
                        's' if isinstance(
                            result.response_length,
                            list) else ''}: {
                        result.response_length}")

                # 취약점 출력
                print(f"\nVulnerability:")
                for vuln in result.vulnerabilities:
                    if vuln.detected:
                        print("=" * 15)
                        print(f"Type: {vuln.type}")
                        print(f"Pattern_Type: {vuln.pattern_type}")
                        print(f"Confidence: {vuln.confidence}%")
                        print(f"Evidence: {vuln.evidence}")
                        if vuln.encoding_info:
                            print(f"Encoding: {vuln.encoding_info}")
                print("-" * 50)

            print(f"\n실행 시간: {time.time() - start_time:.2f}초")

        except Exception as e:
            print(f"Error: {e}")

    asyncio.run(test())
