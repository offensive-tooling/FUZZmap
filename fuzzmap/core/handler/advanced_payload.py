from typing import Optional, List, Dict, Any
import asyncio
import json
from enum import Enum
from fuzzmap.core.util.util import Util
from fuzzmap.core.handler.request_payload import RequestPayloadHandler
from dataclasses import dataclass


class DetailVuln(Enum):
    ERROR_BASED_SQLI = "error_based"
    TIME_BASED_SQLI = "time_based"
    BOOLEAN_BASED_SQLI = "boolean_based"


class Vuln(Enum):
    SQLI = "sqli"
    XSS = "xss"
    SSTI = "ssti"
    UNKNOWN = "unknown"


@dataclass
class AnalysisResult:
    detected: bool
    DetailVuln: Optional[str]
    evidence: Optional[str]
    payload: Optional[str]
    confidence: int


class AdvancedPayloadHandler:
    def __init__(self, vuln: Vuln, pattern: DetailVuln, url: str, method: str, params: dict, dbms: Optional[str] = None):
        self.requests_handler = RequestPayloadHandler()

        self.vuln = vuln
        self.pattern = pattern
        self.url = url
        self.method = method
        self.params = params
        self.dbms = dbms

    def _load_payloads(self, vuln: str) -> dict:
        file_mapping = {
            "sqli": "fuzzmap/core/handler/payloads/sqli_payload.json",
            "xss": "./payloads/xss_payload.json",
            "ssti": "./payloads/ssti_payload.json"
        }
        filepath = file_mapping.get(vuln)
        if not filepath:
            raise ValueError(f"Unsupported vulnerability type: {vuln}")
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"File not found: {filepath}")
            return {}
        except json.JSONDecodeError as e:
            print(f"Invalid JSON format in file: {filepath}. Error: {e}")
            return {}

        

    def _parse_payloads(self) -> List[dict]:
        payloads = self._load_payloads(self.vuln.value)
        if not payloads:
            return []
        pattern_payloads = payloads.get(self.pattern.value, [])
        if self.dbms:
            return [payload for payload in pattern_payloads if payload.get("dbms") == self.dbms]
        return pattern_payloads.insert("")

    async def _send_payloads(self, payloads: List[str], type: str="client_side"):
        if type == "server_side":
            tasks = [self.requests_handler.send_serverside(
                url=self.url,
                params=self.params,
                method=self.method,
                payloads=payloads
            )]
        elif type == "client_side":
            tasks = [self.requests_handler.send_clientside(
                url=self.url,
                params=self.params,
                method=self.method,
                payloads=payloads
            )]
        results = await asyncio.gather(*tasks)
        return results[0] if len(results) == 1 else results

    async def _analyze_time_based(self, responses) -> List[AnalysisResult]:
        results = []
        if not responses:
            return results

        times = [response.response_time for response in responses]
        avg_response_time = sum(times) / len(times) if times else 0
        detected = avg_response_time > 10

        for response in responses:
            results.append(
                AnalysisResult(
                    detected=detected,
                    DetailVuln="Time-Based SQL Injection",
                    evidence=f"Average Response Time: {avg_response_time:.2f} seconds",
                    payload=response.payload if detected else None,
                    confidence=100
                )
            )
        return results


    async def _analyze_boolean_based(self, responses) -> List[AnalysisResult]:
        results = []
        if not responses:
            return results


        normal_response = responses[0].response_text

        for response in responses[1:]:
            detected = len(response.response_text) - len(normal_response) > 50
            results.append(
                AnalysisResult(
                    detected=detected,
                    DetailVuln="Boolean-Based SQL Injection",
                    evidence=f"Payload: {response.payload}" if detected else None,
                    payload=response.payload if detected else None,
                    confidence=90 if detected else 10
                )
            )
        return results


    async def _analyze_error_based(self, responses) -> List[AnalysisResult]:
        results = []
        if not responses:
            return results

        for response in responses:
            detected = "error" in response.response_text.lower()
            results.append(
                AnalysisResult(
                    detected=detected,
                    DetailVuln="Error-Based SQL Injection",
                    evidence="Error message observed in response" if detected else None,
                    payload=response.payload if detected else None,
                    confidence=100
                )
            )
        return results

    async def _advanced_sqli(self):
        payloads = [payload["payload"] for payload in self._parse_payloads()]
        responses = await self._send_payloads(payloads)
        if self.pattern == DetailVuln.TIME_BASED_SQLI:
            return await self._analyze_time_based(responses)
        elif self.pattern == DetailVuln.BOOLEAN_BASED_SQLI:
            return await self._analyze_boolean_based(responses)
        elif self.pattern == DetailVuln.ERROR_BASED_SQLI:
            return await self._analyze_error_based(responses)

    async def run(self) -> List[AnalysisResult]:
        if self.vuln == Vuln.SQLI:
            return await self._advanced_sqli()
        elif self.vuln == Vuln.XSS:
            pass
        elif self.vuln == Vuln.SSTI:
            pass
        return []


if __name__ == "__main__":
    test_url = "http://localhost/login.php"
    test_params = {"name": ""}
    test_method = "POST"

    fuzzer = AdvancedPayloadHandler(
        vuln=Vuln.SQLI,
        pattern=DetailVuln.BOOLEAN_BASED_SQLI,
        url=test_url,
        method=test_method,
        params=test_params,
        dbms=None
    )
    results = asyncio.run(fuzzer.run())
    for result in results:
        print(f"{result.detected}")
        print(f"{result.DetailVuln}")
        print(f"{result.evidence}")
        print(f"{result.payload}")
        print(f"{result.confidence}")

