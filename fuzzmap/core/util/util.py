import re
import random
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

    @staticmethod
    def get_random_user_agent() -> str:
        """랜덤 User-Agent 반환"""
        user_agents = [
            # 데스크톱 브라우저
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            
            # 모바일 브라우저
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
            
            # 봇/크롤러 (테스트용)
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 (compatible; DuckDuckBot-Https/1.1; https://duckduckgo.com/duckduckbot)"
        ]
        return random.choice(user_agents) 


if __name__ == "__main__":
    # Util 클래스의 인스턴스 생성
    util = Util()
    
    # 1. URL 파라미터 추출 테스트
    test_url = "http://example.com/path?param1=value1&param2=value2"
    print("\n1. URL 파라미터 추출 테스트:")
    print(f"URL: {test_url}")
    print(f"추출된 파라미터: {util.extract_params(test_url)}")
    
    # 2. URL 유효성 검사 테스트
    test_urls = [
        "http://example.com",
        "https://test.com/path",
        "invalid-url",
        "ftp://files.com"
    ]
    print("\n2. URL 유효성 검사 테스트:")
    for url in test_urls:
        print(f"URL: {url} -> 유효함: {util.is_valid_url(url)}")
    
    # 3. 페이로드 인코딩 테스트
    test_payloads = [
        "<script>alert(1)</script>",
        "' OR '1'='1",
        "admin' --"
    ]
    print("\n3. 페이로드 인코딩 테스트:")
    for payload in test_payloads:
        print(f"원본: {payload}")
        print(f"인코딩: {util.encode_payload(payload)}")
    
    # 4. URL 정규화 테스트
    test_urls = [
        "example.com/",
        "http://test.com/",
        "https://secure.com/path/"
    ]
    print("\n4. URL 정규화 테스트:")
    for url in test_urls:
        print(f"원본: {url}")
        print(f"정규화: {util.normalize_url(url)}")
    
    # 5. 랜덤 User-Agent 테스트
    print("\n5. 랜덤 User-Agent 테스트:")
    for _ in range(3):
        print(f"랜덤 User-Agent: {util.get_random_user_agent()}") 