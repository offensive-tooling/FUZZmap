import argparse
import sys

class Parser:
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description="🛡️ FUZZmap - Web Vulnerability Fuzzer",
            add_help=False  # 자동 도움말 메시지 비활성화
        )
        
        # 인자 설정
        self.parser.add_argument('-t', '--target', help="🎯 Target URL to scan")  # required=True 제거
        self.parser.add_argument('-m', '--method', help="📡 HTTP method (GET/POST)", 
                                choices=['GET', 'POST'], default='GET')
        self.parser.add_argument('-p', '--param', help="🔍 Parameters to test (comma separated)")
        self.parser.add_argument('-rp', '--recon_param', help="🔎 Enable parameter reconnaissance", 
                                action='store_true')
        self.parser.add_argument('-v', '--verbose', help="📝 Enable verbose output", 
                                action='store_true')
        # 도움말 인자 수동 추가
        self.parser.add_argument('-h', '--help', help="ℹ️ Show this help message", 
                                action='store_true')

    def parse_args(self):
        """인자 파싱"""
        args = self.parser.parse_args()
        
        # 직접 도움말 플래그 확인
        if args.help:
            self.parser.print_help()
            sys.exit(0)
            
        # 필수 인자 수동 검증
        if not args.target and len(sys.argv) > 1:  # 인자가 있을 때만 검증
            print("🚫 오류: 대상 URL(-t/--target)은 필수 인자입니다")
            sys.exit(1)
            
        if args.param:
            args.param = [p.strip() for p in args.param.split(",")]
        return args 