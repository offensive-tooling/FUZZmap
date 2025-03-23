#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FUZZmap main entry point
"""

import sys
import asyncio
from fuzzmap.fuzzmap import main

def run_main():
    """비동기 메인 함수를 실행하는 래퍼 함수"""
    try:
        # 인자가 없을 때 배너 표시
        if len(sys.argv) == 1:
            # CLI 모듈 임포트
            try:
                from fuzzmap.core.cli.cli import CLI
                cli = CLI()
                cli.print_banner()
                cli.print_usage()
                return
            except ImportError:
                try:
                    from core.cli.cli import CLI
                    cli = CLI()
                    cli.print_banner()
                    cli.print_usage()
                    return
                except ImportError:
                    pass
                    
        if sys.platform.startswith('win'):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\033[93m[!] 사용자에 의해 중단되었습니다.\033[0m")
        sys.exit(1)
    except Exception as e:
        print(f"\n\033[91m[!] 오류 발생: {str(e)}\033[0m")
        sys.exit(1)

if __name__ == "__main__":
    run_main() 