from typing import Optional, List, Dict, Any
from statistics import mean
from enum import Enum
from fuzzmap.core.util.util import Util
from fuzzmap.core.handler.request_payload import RequestPayloadHandler
from dataclasses import dataclass

import asyncio
import re

class DetailVuln(Enum):
    ERROR_BASED_SQLI = "error_based"
    TIME_BASED_SQLI = "time_based"
    BOOLEAN_BASED_SQLI = "boolean_based"
    XSS = "normal"

class Vuln(Enum):
    SQLI = "sqli"
    XSS = "xss"
    SSTI = "ssti"
    UNKNOWN = "unknown"

@dataclass
class AnalysisResult:
    detected: bool
    detailvuln: Optional[str]
    evidence: Optional[str]
    payload: Optional[str]
    confidence: int
    context: Optional[str] = None

class AdvancedPayloadHandler:
    def __init__(self, vuln: Vuln, pattern: DetailVuln,
                        url: str, method: str, params: dict, 
                        dbms: Optional[str] = None, user_agent: Optional[str] = None,
                        cookies: Optional[Dict[str, str]] = None):
        self.requests_handler = RequestPayloadHandler()
        self.vuln = vuln
        self.pattern = pattern
        self.url = url
        self.method = method
        self.params = params
        self.dbms = dbms
        self.user_agent = user_agent
        self.cookies = cookies
        self.payloads_mapping = {
            "sqli": "handler/payloads/sqli_payload.json",
            "xss": ".handler/payloads/xss_payload.json",
            "ssti": "./payloads/ssti_payload.json"
        }
        filepath = self.payloads_mapping.get(self.vuln.value)
        self.payloads = Util.load_json(filepath)

    def _parse_sql_payloads(self) -> List[dict]:
        pattern_payloads = self.payloads.get(self.pattern, [])
        if self.dbms:
            return [payload for payload in pattern_payloads if payload.get("dbms") == self.dbms]
        return pattern_payloads
    
    def _parse_xss_payloads(self) -> List[dict]:
        pattern_payload = self.payloads.get(self.pattern, {})
        payloads = pattern_payload['payloads']
        return payloads
    
    def _compile_sql_patterns(self):
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

    def _get_context(self, text: str, pattern: str, window: int = 50) -> str:
        pos = text.find(pattern)
        return text[max(0, pos - window):min(len(text),
                                            pos + len(pattern) + window)]

    async def _send_payloads(self, payloads: List[str], type: str="server_side"):
        if type == "server_side":
            tasks = [self.requests_handler.send_serverside(
                url=self.url,
                params=self.params,
                method=self.method,
                payloads=payloads,
                user_agent=self.user_agent,
                cookies=self.cookies
            )]
        elif type == "client_side":
            tasks = [self.requests_handler.send_clientside(
                url=self.url,
                params=self.params,
                method=self.method,
                payloads=payloads,
                user_agent=self.user_agent,
                cookies=self.cookies
            )]
        results = await asyncio.gather(*tasks)
        return results[0] if len(results) == 1 else results

    async def __analyze_time_based(self, responses: List, payloads: List) -> List[AnalysisResult]:
        results = []
        compare_responses = await self._send_payloads(payloads)
        
        if not responses or not compare_responses:
            return results
        min_len = min(len(responses), len(compare_responses))

        for i in range(min_len):  
            response_time_avg = mean([responses[i].response_time, compare_responses[i].response_time]) 
            detected = response_time_avg > 10

            results.append(
                AnalysisResult(
                    detected=detected,
                    detailvuln="Time-Based SQL Injection",
                    evidence=f"Avg Response Time: {response_time_avg:.2f}s DBMS: {self.dbms}",
                    payload=responses[i].payload if detected else None,
                    confidence=100 if detected else 0
                )
            )
        return results

    async def __analyze_boolean_based(self, responses) -> List[AnalysisResult]:
        results = []
        if not responses:
            return results

        normal_response = responses[0].response_text

        for response in responses[1:]:
            detected = abs(len(response.response_text) - len(normal_response)) > 500
            results.append(
                AnalysisResult(
                    detected=detected,
                    detailvuln="Boolean-Based SQL Injection",
                    evidence=f"Shows a significant difference from normal input DBMS: {self.dbms}" if detected else None,
                    payload=response.payload if detected else None,
                    confidence=100 if detected else 0
                )
            )
        return results

    async def __analyze_error_based(self, responses) -> List[AnalysisResult]:
        results = []    
        if not responses:
            return results
        sql_patterns = self._compile_sql_patterns()
        for response in responses:
            for dbms_type, dbms_info in sql_patterns.items():
                for pattern in dbms_info["patterns"]:
                    if match := pattern.search(response.response_text):
                        context = self._get_context(response.response_text, match.group(0))
                        detected = True
                        results.append(
                        AnalysisResult(
                            detected=detected,
                            detailvuln="Error-Based SQL Injection",
                            evidence=f"Error message observed in response DBMS: {self.dbms} " if detected else None,
                            payload=response.payload if detected else None,
                            context=context,
                            confidence=100 if detected else 0
                        )
                    )
                        break
                    else:
                        detected = False
        return results

    async def __analyze_xss(self, responses) -> List[AnalysisResult]:
        results = []
        if not responses:
            return results
        
        for response in responses:
            detected = response.dialog_triggered
            results.append(
                AnalysisResult(
                    detected=detected,
                    detailvuln="Reflected XSS",
                    evidence=f"{response.dialog_type} Reflected XSS Triggered" if detected else None,
                    payload=response.payload if detected else None,
                    context=response.dialog_message if detected and response.dialog_message else None,
                    confidence=100 if detected else 0
                )
            )
        return results

    async def _advanced_sqli(self):
        payloads = [payload["payload"] for payload in self._parse_sql_payloads()]
        responses = await self._send_payloads(payloads)
        if self.pattern == DetailVuln.TIME_BASED_SQLI.value:
            return await self.__analyze_time_based(responses, payloads)
        elif self.pattern == DetailVuln.BOOLEAN_BASED_SQLI.value:
            return await self.__analyze_boolean_based(responses)
        elif self.pattern == DetailVuln.ERROR_BASED_SQLI.value:
            return await self.__analyze_error_based(responses)
    
    async def _advanced_xss(self):
        payloads = self._parse_xss_payloads()
        responses = await self._send_payloads(payloads, type="client_side")
        if self.pattern == DetailVuln.XSS.value:
            return await self.__analyze_xss(responses)

    async def run(self) -> List[AnalysisResult]:
        if self.vuln == Vuln.SQLI:
            return await self._advanced_sqli()
        elif self.vuln == Vuln.XSS:
            return await self._advanced_xss()
        elif self.vuln == Vuln.SSTI:
            pass
        return []

if __name__ == "__main__":
    test_url = "http://localhost/index.php?type=title"
    test_params = {"search": ""}
    test_method = "GET"

    fuzzer = AdvancedPayloadHandler(
        vuln = Vuln.XSS,
        pattern = "normal",
        url = test_url,
        method = test_method,
        params = test_params
    )
    results = asyncio.run(fuzzer.run())
    for result in results:
        print(f"Detected: {result.detected}")
        print(f"Detail_Vuln: {result.detailvuln}")
        print(f"evidence: {result.evidence}")
        print(f"payload: {result.payload}")
        print(f"context: {result.context}")
        print(f"confidence: {result.confidence}")
