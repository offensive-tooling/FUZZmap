from typing import Dict, List
import requests
from ..logging.log import Logger
from ..util.util import Util

class ParamRecon:
    def __init__(self):
        self.logger = Logger()
        self.util = Util()

    def collect(self, url: str, specific_param: str = None) -> List[str]:
        """URL에서 파라미터 수집"""
        try:
            if specific_param:
                return [specific_param]
                
            params = self.util.extract_params(url)
            return list(params.keys())
            
        except Exception as e:
            self.logger.error(f"파라미터 수집 중 오류 발생: {str(e)}")
            return []

    def analyze_param(self, url: str, param: str) -> Dict:
        """파라미터 분석"""
        try:
            response = requests.get(url)
            return {
                "param": param,
                "type": self._detect_param_type(response.text),
                "reflection": self._check_reflection(response.text, param)
            }
        except Exception as e:
            self.logger.error(f"파라미터 분석 중 오류 발생: {str(e)}")
            return {}

    def _detect_param_type(self, content: str) -> str:
        """파라미터 타입 탐지"""
        # 구현 예정
        return "unknown"

    def _check_reflection(self, content: str, param: str) -> bool:
        """파라미터 값 반영 여부 확인"""
        # 구현 예정
        return False 