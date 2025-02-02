from typing import Dict, List, Optional
from fuzzmap.core.handler.param_recon import ParamReconHandler, Param
from fuzzmap.core.handler.common_payload import CommonPayloadHandler, ScanResult
from fuzzmap.core.logging.log import Logger
import asyncio

class Controller:
    def __init__(self, target: str, method: str = "GET", 
                 param: Optional[List[str]] = None, 
                 recon_param: bool = False):
        """
        컨트롤러 초기화
        Args:
            target: 대상 URL
            method: HTTP 메서드 (GET/POST)
            param: 수동으로 지정된 파라미터 목록
            recon_param: 파라미터 자동 수집 여부
        """
        self.target = target
        self.method = method.upper()
        self.params = param if param else []
        self.recon_param = recon_param
        self.logger = Logger()
        self.param_recon = ParamReconHandler(self.target)
        self.common_payload = CommonPayloadHandler()

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

    async def _scan_vulnerabilities(self, params: List[Param]) -> Dict[str, List[ScanResult]]:
        """취약점 스캔 실행"""
        vulnerabilities = {}
        try:
            for param in params:
                param_info = {
                    "method": param.method,
                    "path": param.path
                }

                print(f"===============================================================================")
                print(f"URL: {param.url}")
                print(f"param name: {param.name}")
                print(f"param info: {param_info}")
                print(f"===============================================================================")

                scan_results = await self.common_payload.scan(
                    url=param.url,
                    param_name=param.name,
                    param_info=param_info
                )
                if scan_results:
                    vulnerabilities[param.name] = scan_results
                    
                    # 스캔 결과 출력
                    print(f"\n[+] Vulnerability Scan Results for {param.name}:")
                    for result in scan_results:
                        print(f"\nPayload: {result.payload}")
                        print(f"Response Time: {result.response_time:.2f}s")
                        print(f"Alert Triggered: {result.alert_triggered}")
                        if result.alert_message:
                            print(f"Alert Message: {result.alert_message}")
                        
                        for vuln in result.vulnerabilities:
                            if vuln.detected:
                                print(f"Type: {vuln.type}")
                                print(f"Pattern Type: {vuln.pattern_type}")
                                print(f"Confidence: {vuln.confidence}%")
                                print(f"Evidence: {vuln.evidence}")
                                if vuln.encoding_info:
                                    print(f"Encoding: {vuln.encoding_info}")
                                print("-" * 50)
                
        except Exception as e:
            self.logger.error(f"취약점 스캔 중 오류 발생: {str(e)}")
        
        return vulnerabilities

    async def async_run(self) -> Dict:
        """비동기 실행 메서드"""
        try:
            results = {
                "parameters": [],
                "vulnerabilities": {}
            }

            # 파라미터 수집
            collected_params = []
            if self.recon_param:
                collected_params = await self._collect_parameters()
                if collected_params:
                    results["parameters"] = collected_params
                    self.params = [param.name for param in collected_params]
                    
                    print("\nCollected parameters:")
                    for param in collected_params:
                        print(
                            f"URL: {param.url}, "
                            f"Name: {param.name}, "
                            f"Value: {param.value}, "
                            f"Type: {param.param_type}, "
                            f"Method: {param.method}, "
                            f"Path: {param.path}"
                        )
            
            # 지정된 파라미터가 있는 경우
            elif self.params:
                collected_params = [
                    Param(
                        url=self.target,
                        name=param,
                        value="",
                        param_type="user-specified",
                        method=self.method,
                        path=""
                    )
                    for param in self.params
                ]
                results["parameters"] = collected_params
                print("\nSpecified parameters:")
                for param in collected_params:
                    print(
                        f"URL: {param.url}, "
                        f"Name: {param.name}, "
                        f"Value: {param.value}, "
                        f"Type: {param.param_type}, "
                        f"Method: {param.method}, "
                        f"Path: {param.path}"
                    )

            # 취약점 스캔 실행
            if collected_params:
                results["vulnerabilities"] = await self._scan_vulnerabilities(collected_params)

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
        # # 파라미터 지정 테스트
        # print("\n[*] Parameter Specification Test")
        # print("-" * 50)
        # controller = Controller(
        #     target="http://testphp.vulnweb.com/listproducts.php",
        #     method="GET",
        #     param=["cat"]
        # )
        # results = await controller.async_run()
        
        # 파라미터 자동 탐지 테스트
        print("\n[*] Parameter Reconnaissance Test")
        print("-" * 50)
        controller = Controller(
            target="http://testphp.vulnweb.com/listproducts.php?cat=1234",
            recon_param=True
        )
        results = await controller.async_run()

    asyncio.run(main())
