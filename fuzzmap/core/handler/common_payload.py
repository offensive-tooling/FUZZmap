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
    response_text: str
    response_time: float
    response_length: Optional[int]
    vulnerabilities: List[VulnerabilityInfo]
    alert_triggered: bool = False
    alert_message: str = ""


class CommonPayloadHandler:
    def __init__(self):
        self._payloads = Util.load_json(
            'handler/payloads/common_payload.json')['payloads']
        self._analyzer = ResponseAnalyzer(self._payloads)
        self._classifier = VulnerabilityClassifier()
        self.Logger = Logger()

    async def scan(self, url: str, param_name: str,
                   param_info: Dict) -> List[ScanResult]:
        try:
            method = param_info.get('method', 'GET')
            params = {param_name: ""}
            results = []

            for payload_info in self._payloads:
                vuln_types = [v['type']
                              for v in payload_info.get('vulnerabilities', [])]
                payload = payload_info['payload']
                payloads = [payload] if isinstance(payload, str) else payload

                if 'xss' in vuln_types:
                    responses = await RequestPayloadHandler.send_clientside(
                        url, params, method, payloads
                    )
                else:
                    responses = await RequestPayloadHandler.send_serverside(
                        url, params, method, payloads
                    )

                for response in responses:
                    result = ScanResult(
                        param_name=param_name,
                        payload=response.payload,
                        response_text=response.response_text,
                        response_time=response.response_time,
                        response_length=response.response_length,
                        vulnerabilities=[
                            VulnerabilityInfo(
                                **vuln) for vuln in payload_info.get(
                                'vulnerabilities',
                                [])],
                        alert_triggered=getattr(
                            response,
                            'alert_triggered',
                            False),
                        alert_message=getattr(
                            response,
                            'alert_message',
                            ''))

                    analyzed_result = self._analyzer.analyze_res(result)
                    classified_result = self._classifier.classify_vuln(
                        analyzed_result)
                    results.append(classified_result)

            return results

        except Exception as e:
            self.Logger.error(f"Scan failed: {e}")
            return []


class ResponseAnalyzer:
    def __init__(self, payloads=None):
        self.sql_patterns = Util.load_json('handler/config/sql_error.json')
        self._payloads = payloads if payloads else []  # payloads 저장

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
            for pattern in dbms_info.get("patterns", []):
                if match := re.search(pattern, response, re.IGNORECASE):
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

        tag_pattern = r'<([a-z0-9]+)[^>]*>([^<]*)</\1>'
        if tag_match := re.search(tag_pattern, payload, re.I):
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

        partial_pattern = r'<[^>]*>'
        if injected_partial := re.search(partial_pattern, payload, re.I):
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

        if match := re.search(r'\b1879080904\b', response_text):
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

        common_handler = CommonPayloadHandler()
        results = await common_handler.scan(
            url=test_url,
            param_name=test_param["name"],
            param_info=test_param
        )

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

    asyncio.run(test())
