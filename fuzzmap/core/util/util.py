import re
import os
import random
import json
import urllib.parse
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

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

    @staticmethod
    def load_json(filepath: str) -> Dict:
        try:
            # fuzzmap 패키지 루트 경로 찾기
            module_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            
            # 여러 가능한 경로 시도
            possible_paths = [
                # 1. 절대 경로로 시도
                filepath,
                # 2. core 디렉토리 기준 경로
                os.path.join(module_dir, "core", filepath),
                # 3. fuzzmap 패키지 루트 기준 경로
                os.path.join(module_dir, filepath),
                # 4. 설치된 패키지 내 경로
                os.path.join(module_dir, "core", "handler", "payloads", os.path.basename(filepath)),
            ]
            
            # 각 경로 시도
            for path in possible_paths:
                if os.path.exists(path):
                    with open(path, 'r', encoding='utf-8') as f:
                        return json.load(f)
            
            # 절대 경로 출력 (디버깅용)
            print(f"시도한 경로들: {possible_paths}")
            print(f"현재 디렉토리: {os.getcwd()}")
            
            # 사이트 패키지 경로에서 페이로드 파일 찾기 시도
            import site
            for site_dir in site.getsitepackages():
                fuzzmap_dir = os.path.join(site_dir, "fuzzmap")
                if os.path.exists(fuzzmap_dir):
                    path = os.path.join(fuzzmap_dir, "core", "handler", "payloads", os.path.basename(filepath))
                    if os.path.exists(path):
                        with open(path, 'r', encoding='utf-8') as f:
                            return json.load(f)
            
            print(f"파일을 찾을 수 없습니다: {filepath}")
            # 파일이 없으면 빈 객체 반환
            return {}
        except FileNotFoundError as e:
            print(f"File not found: {filepath}")
            return {}
        except json.JSONDecodeError as e:
            print(f"Invalid JSON: {filepath}")
            return {}

    @staticmethod
    def combine_url_with_path(base_url: str, path: str) -> str:
        """베이스 URL과 path를 결합
        Args:
            base_url: 기본 URL (예: http://example.com/test.php)
            path: 추가할 경로 (예: /search.php)
        Returns:
            str: 결합된 URL
        """
        # path가 없거나 비어있거나 단순 '/'인 경우 base_url 반환
        if not path or path.strip() == '/':
            return base_url
        
        # base_url에서 기존 path 제거하고 scheme과 netloc만 사용
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        # path가 절대 경로면 그대로 사용, 상대 경로면 /를 추가
        if not path.startswith('/'):
            path = '/' + path
        
        # path가 의미있는 endpoint를 가리키는지 확인
        # 단순히 파일 확장자나 경로가 있는지 체크
        if '.' in path or '/' not in path[-1:]:
            return urljoin(base, path)
        else:
            return base_url

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
    
    # 6. URL 결합 테스트
    print("\n6. URL 결합 테스트:")
    test_cases = [
        ("http://example.com/test.php", ""),  # 빈 path
        ("http://example.com/test.php", "/"), # 단순 슬래시
        ("http://example.com/test.php", "search.php"), # 상대 경로
        ("http://example.com/test.php", "/search.php"), # 절대 경로
        ("http://example.com/test.php", "api/"), # 의미없는 경로
        ("http://example.com/test.php", "/api/v1/search.php") # 복잡한 경로
    ]
    
    for base_url, path in test_cases:
        combined = Util.combine_url_with_path(base_url, path)
        print(f"Base URL: {base_url}")
        print(f"Path: {path}")
        print(f"Combined: {combined}\n") 