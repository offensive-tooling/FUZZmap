#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FUZZmap - Web Application Vulnerability Fuzzing Tool
"""

import sys
import subprocess
import asyncio
import importlib.util

async def main():
    """메인 함수"""
    try:
        # Playwright 확인 및 설치
        try:
            import playwright
        except ImportError:
            print("\033[93m[!] Playwright가 설치되어 있지 않습니다. 설치를 시도합니다...\033[0m")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "playwright"])
                # 브라우저도 설치
                subprocess.check_call([sys.executable, "-m", "playwright", "install"])
                print("\033[92m[+] Playwright 설치 완료!\033[0m")
                # 모듈 다시 로드
                if "playwright" in sys.modules:
                    importlib.reload(sys.modules["playwright"])
                else:
                    import playwright
            except Exception as e:
                print(f"\033[91m[!] Playwright 설치 실패: {e}\033[0m")
                print("\033[93m[!] 수동으로 'pip install playwright' 후 'playwright install' 명령을 실행하세요\033[0m")
                return 1
        
        # CLI 모듈 임포트
        try:
            # 패키지로 설치된 경우
            from fuzzmap.core.cli.cli import CLI
        except ImportError:
            # 직접 실행하는 경우
            try:
                from core.cli.cli import CLI
            except ImportError:
                print("\033[91m[!] CLI 모듈을 찾을 수 없습니다. 패키지가 올바르게 설치되었는지 확인하세요.\033[0m")
                sys.exit(1)
        
        # 인자가 없을 때는 배너만 표시
        if len(sys.argv) == 1:
            cli = CLI()
            cli.print_banner()
            cli.print_usage()
            return 0
            
        # CLI 실행
        cli = CLI()
        results = await cli.async_run()
        
        return results
    except Exception as e:
        print(f"\n\033[91m[!] FUZZmap 실행 중 오류 발생: {str(e)}\033[0m")
        return None

if __name__ == "__main__":
    asyncio.run(main()) 