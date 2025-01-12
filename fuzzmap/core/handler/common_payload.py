import json
import os
from typing import Dict, List
from ..logging.log import Logger

class CommonPayload:
    def __init__(self):
        self.logger = Logger()
        self.payloads = self._load_payloads()

    def _load_payloads(self) -> Dict:
        """페이로드 파일 로드"""
        try:
            payload_path = os.path.join(
                os.path.dirname(__file__), 
                "payloads/common_payload.json"
            )
            with open(payload_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"페이로드 로드 중 오류 발생: {str(e)}")
            return {}

    def test(self, url: str, params: List[str]) -> Dict:
        """공통 페이로드 테스트 실행"""
        results = {}
        try:
            for param in params:
                param_results = []
                for payload in self.payloads:
                    result = self._test_payload(url, param, payload)
                    if result:
                        param_results.append(result)
                results[param] = param_results
            return results
        except Exception as e:
            self.logger.error(f"페이로드 테스트 중 오류 발생: {str(e)}")
            return {}

    def _test_payload(self, url: str, param: str, payload: Dict) -> Dict:
        """개별 페이로드 테스트"""
        # 구현 예정
        return {} 