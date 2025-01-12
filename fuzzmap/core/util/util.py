import re
import urllib.parse
from typing import Dict, List, Optional

class Util:
    @staticmethod
    def extract_params(url: str) -> Dict[str, str]:
        """URL에서 파라미터 추출"""
        parsed = urllib.parse.urlparse(url)
        return dict(urllib.parse.parse_qsl(parsed.query))

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """URL 유효성 검사"""
        try:
            result = urllib.parse.urlparse(url)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False

    @staticmethod
    def encode_payload(payload: str) -> str:
        """페이로드 인코딩"""
        return urllib.parse.quote(payload)

    @staticmethod
    def normalize_url(url: str) -> str:
        """URL 정규화"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/') 