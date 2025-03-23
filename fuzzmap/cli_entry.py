#!/usr/bin/env python3
"""
FUZZmap CLI 진입점 모듈
"""
import sys
import subprocess
import asyncio
import importlib.util

def main():
    """명령줄 도구 진입점"""
    try:
        # 먼저 playwright가 설치되어 있는지 확인
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
                
        # fuzzmap.core.cli.cli 모듈 임포트
        from fuzzmap.core.cli.cli import CLI
        
        cli = CLI()
        if sys.platform.startswith('win'):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        # 비동기 실행 처리
        loop = asyncio.get_event_loop()
        results = loop.run_until_complete(cli.async_run())
        
        return 0 if results else 1
    except KeyboardInterrupt:
        print("\n\033[93m[!] 사용자에 의해 중단되었습니다.\033[0m")
        return 1
    except Exception as e:
        print(f"\n\033[91m[!] 오류 발생: {str(e)}\033[0m")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 