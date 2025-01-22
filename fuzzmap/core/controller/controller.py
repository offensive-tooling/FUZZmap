from typing import Dict, List, Optional
from fuzzmap.core.handler.param_recon import ParamReconHandler, Param
from fuzzmap.core.handler.common_payload import CommonPayload
from fuzzmap.core.handler.advanced_payload import AdvancedPayload
from fuzzmap.core.logging.log import Logger
import asyncio

class Controller:
    def __init__(self, target: str, method: str = "GET", 
                 param: Optional[List[str]] = None, 
                 recon_param: bool = False):
        self.target = target
        self.method = method.upper()
        self.params = param if param else []
        self.recon_param = recon_param
        self.logger = Logger()
        self.param_recon = ParamReconHandler(self.target)
        self.common_payload = CommonPayload()
        self.advanced_payload = AdvancedPayload()

    def run(self) -> Dict:
        """동기 실행 메서드 - CLI에서 호출됨"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(self.async_run())
            finally:
                loop.close()
        except Exception as e:
            self.logger.error(f"Controller run error: {str(e)}")
            return {"parameters": [], "vulnerabilities": {}}

    async def _collect_parameters(self) -> List[Param]:
        """파라미터 자동 탐지 실행"""
        try:
            return await self.param_recon.collect_parameters()
        except Exception as e:
            self.logger.error(f"파라미터 탐지 중 오류 발생: {str(e)}")
            return []

    async def async_run(self) -> Dict:
        """비동기 실행 메서드"""
        try:
            results = {
                "parameters": [],
                "vulnerabilities": {}
            }

            # 파라미터 수집
            if self.recon_param:
                collected_params = await self._collect_parameters()
                if collected_params:
                    results["parameters"] = collected_params
                    self.params = [param.name for param in collected_params]
                    
                    # 수집된 파라미터 출력 (param_recon.py와 동일한 형식)
                    print("\nSingle URL parameters:")
                    for param in collected_params:
                        print(
                            f"Name: {param.name}, "
                            f"Value: {param.value}, "
                            f"Type: {param.param_type}, "
                            f"Method: {param.method}"
                        )
        
            # 지정된 파라미터가 있는 경우
            elif self.params:
                results["parameters"] = [
                    Param(name=param, value="", param_type="user-specified", method=self.method)
                    for param in self.params
                ]
                # 지정된 파라미터도 동일한 형식으로 출력
                print("\nSpecified parameters:")
                for param in results["parameters"]:
                    print(
                        f"Name: {param.name}, "
                        f"Value: {param.value}, "
                        f"Type: {param.param_type}, "
                        f"Method: {param.method}"
                    )

            # 취약점 스캔 부분은 주석 처리 (현재는 param_recon에만 집중)
            """
            if self.params:
                common_results = await self.common_payload.test(...)
                advanced_results = await self.advanced_payload.test(...)
                if common_results or advanced_results:
                    results["vulnerabilities"] = {...}
            """

            return results
            
        except Exception as e:
            self.logger.error(f"Controller execution error: {str(e)}")
            return {"parameters": [], "vulnerabilities": {}}

#@TODO
'''
1. ParamReconHandler url 값도 같이 출력되도록 처리
2. CommonPayload 리턴 값 확인
3. AdvancedPayload 리턴 값 확인
'''

if __name__ == "__main__":
    async def main():
        # 파라미터 지정 테스트
        print("\n[*] Parameter Specification Test")
        print("-" * 50)
        controller = Controller(
            target="http://testphp.vulnweb.com/listproducts.php",
            method="GET",
            param=["cat"]
        )
        results = await controller.async_run()
        if results.get("parameters") or results.get("vulnerabilities"):
            print("\n[+] Results found:")
            print(results)
        else:
            print("[!] No results found")

        # 파라미터 자동 탐지 테스트
        print("\n[*] Parameter Reconnaissance Test")
        print("-" * 50)
        controller = Controller(
            target="http://testphp.vulnweb.com/login.php",
            recon_param=True
        )
        results = await controller.async_run()
        if results.get("parameters") or results.get("vulnerabilities"):
            print("\n[+] Results found:")
            print(results)
        else:
            print("[!] No results found")

    # 메인 함수 실행
    asyncio.run(main())