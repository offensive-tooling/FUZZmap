from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from fuzzmap.core.handler.param_recon import ParamReconHandler, Param
from fuzzmap.core.handler.common_payload import CommonPayloadHandler, ScanResult
from fuzzmap.core.handler.advanced_payload import AdvancedPayloadHandler, Vuln, DetailVuln
from fuzzmap.core.logging.log import Logger
from fuzzmap.core.util.util import Util
import asyncio


@dataclass
class ControllerResult:
    parameters: List[Param]
    common_vulnerabilities: Dict[str, List[ScanResult]]
    advanced_vulnerabilities: Dict[str, Any]


class Controller:
    def __init__(self, target: str, method: str = "GET", 
                 param: Optional[List[str]] = None, 
                 recon_param: bool = False,
                 max_concurrent: int = 10):
        """
        컨트롤러 초기화
        Args:
            target: 대상 URL
            method: HTTP 메서드 (GET/POST)
            param: 수동으로 지정된 파라미터 목록
            recon_param: 파라미터 자동 수집 여부
            max_concurrent: 최대 동시 실행 수
        """
        self.target = target
        self.method = method.upper()
        self.params = param or []
        self.recon_param = recon_param
        self.max_concurrent = max_concurrent
        self.logger = Logger()
        self.param_recon = ParamReconHandler(self.target)
        self.common_payload = CommonPayloadHandler()
        self.semaphore = asyncio.Semaphore(max_concurrent)

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

    async def _scan_parameter(self, param: Param) -> Optional[List[ScanResult]]:
        """개별 파라미터 스캔 (공통 페이로드)"""
        try:
            async with self.semaphore:
                target_url = Util.combine_url_with_path(param.url, param.path)
                params = {param.name: ""}
                
                self.logger.info(f"Scanning parameter - URL: {target_url}, Name: {param.name}")
                print(f"===============================================================================")
                print(f"URL: {target_url}")
                print(f"param name: {param.name}")
                print(f"method: {param.method}")
                print(f"===============================================================================")

                scan_results = await self.common_payload.scan(
                    url=target_url,
                    params=params,
                    method=param.method
                )

                if scan_results:
                    self._print_scan_results("common", target_url, param.name, param.method, scan_results)
                return scan_results
        except Exception as e:
            self.logger.error(f"Parameter scan error - {param.name}: {str(e)}")
            return None

    async def _advanced_scan_parameter(self, param: Param, initial_results: List[ScanResult]) -> Dict:
        """개별 파라미터 심화 스캔"""
        advanced_results = {}
        try:
            target_url = Util.combine_url_with_path(param.url, param.path)
            params = {param.name: ""}

            for result in initial_results:
                for vuln in result.vulnerabilities:
                    if vuln.detected:
                        # SQL Injection 심화 스캔
                        if vuln.type == "sql_injection":
                            for pattern in [DetailVuln.ERROR_BASED_SQLI, DetailVuln.TIME_BASED_SQLI, DetailVuln.BOOLEAN_BASED_SQLI]:
                                advanced_handler = AdvancedPayloadHandler(
                                    vuln=Vuln.SQLI,
                                    pattern=pattern,
                                    url=target_url,
                                    method=param.method,
                                    params=params
                                )
                                advanced_results[f"sqli_{pattern.value}"] = await advanced_handler.run()

        except Exception as e:
            self.logger.error(f"Advanced scan error - {param.name}: {str(e)}")
        
        return advanced_results

    async def _scan_vulnerabilities(self, params: List[Param]) -> Dict[str, Dict]:
        """취약점 스캔 실행 - 병렬 처리"""
        results = {
            "common": {},
            "advanced": {}
        }
        try:
            # 병렬로 파라미터 스캔 실행
            tasks = [self._scan_parameter(param) for param in params]
            common_results = await asyncio.gather(*tasks)

            # 결과 취합 및 심화 스캔
            for param, common_result in zip(params, common_results):
                if common_result:
                    results["common"][param.name] = common_result
                    # 심화 스캔 실행
                    results["advanced"][param.name] = await self._advanced_scan_parameter(
                        param, common_result
                    )

        except Exception as e:
            self.logger.error(f"Vulnerability scan error: {str(e)}")
        
        return results

    def _print_scan_results(self, handler: str, url: str, param_name: str, method: str, scan_results: List[ScanResult]) -> None:
        """스캔 결과 출력"""
        has_vulnerabilities = False
        
        for result in scan_results:
            vuln_detected = False
            vuln_details = []
            
            for vuln in result.vulnerabilities:
                if vuln.detected:
                    vuln_detected = True
                    has_vulnerabilities = True
                    vuln_details.append({
                        "type": vuln.type,
                        "pattern_type": vuln.pattern_type,
                        "confidence": vuln.confidence,
                        "evidence": vuln.evidence
                    })
            
            if vuln_detected:  # 취약점이 발견된 경우에만 출력
                print(f"\nhandler: {handler}")
                print(f"url: {url}")
                print(f"parameter: {param_name}")
                print(f"method: {method}")
                
                for detail in vuln_details:
                    print(f"Type: {detail['type']}")
                    print(f"Pattern_Type: {detail['pattern_type']}")
                    print(f"payload: {result.payload}")
                    print(f"Confidence: {detail['confidence']}")
                    print(f"Evidence: {detail['evidence']}")
                    
                    if handler == "common":
                        print(f"Response_Time: {result.response_time:.2f}s")
                        if hasattr(result, 'alert_triggered'):
                            print(f"Alert_Triggered: {result.alert_triggered}")
                            if result.alert_message:
                                print(f"Alert_Message: {result.alert_message}")
                print("-" * 66)
            else:
                # 취약점이 없는 경우에도 payload와 confidence 값 출력
                print(f"\nvuln: No vulnerabilities detected for {param_name} parameter")
                print(f"URL: {url}")
                print(f"payload: {result.payload if result.payload else 'No payload used'}")
                print(f"Confidence: {result.confidence if hasattr(result, 'confidence') else 0}")
                print("-" * 66)

    def _print_final_results(self, results: Dict) -> None:
        """최종 결과 출력"""
        print("\nFinal Arrange Result")
        for param_name, vulns in results['vulnerabilities'].items():
            if 'common' in vulns and 'advanced' in vulns:
                common_result = vulns['common'][0]  # 첫 번째 결과 사용
                advanced_result = vulns['advanced'].get('sqli_error_based', [])
                
                if common_result and advanced_result:
                    print(f"handler: common, advanced")
                    print(f"url: {self.target}")
                    print(f"parameter: {param_name}")
                    print(f"method: {self.method}")
                    
                    for vuln in common_result.vulnerabilities:
                        if vuln.detected:
                            print(f"Type: {vuln.type}")
                            print(f"Detected: {vuln.detected}")
                            print(f"Detail_Vuln: Error-Based SQL Injection")
                            print(f"Common_payload: {common_result.payload}")
                            print(f"Common_Confidence: {vuln.confidence}")
                    
                    for adv_result in advanced_result:
                        if adv_result.detected:
                            print(f"Advanced_payload: {adv_result.payload}")
                            print(f"Advanced_Confidence: {adv_result.confidence}")
                    print()

    def _save_results(self, results: Dict, output_file: str = "scan_results.txt") -> None:
        """스캔 결과 파일 저장"""
        try:
            with open(output_file, 'w') as f:
                for param_name, vulns in results['vulnerabilities'].items():
                    # Common 핸들러 결과 저장
                    if 'common' in vulns:
                        for result in vulns['common']:
                            vuln_detected = False
                            for vuln in result.vulnerabilities:
                                if vuln.detected:
                                    vuln_detected = True
                                    f.write(f"handler: common\n")
                                    f.write(f"url: {self.target}\n")
                                    f.write(f"parameter: {param_name}\n")
                                    f.write(f"method: {self.method}\n")
                                    f.write(f"Type: {vuln.type}\n")
                                    f.write(f"Pattern_Type: {vuln.pattern_type}\n")
                                    f.write(f"payload: {result.payload}\n")
                                    f.write(f"Confidence: {vuln.confidence}\n")
                                    f.write(f"Evidence: {vuln.evidence}\n")
                                    f.write(f"Response_Time: {result.response_time:.2f}s\n")
                                    if hasattr(result, 'alert_triggered'):
                                        f.write(f"Alert_Triggered: {result.alert_triggered}\n")
                                        if result.alert_message:
                                            f.write(f"Alert_Message: {result.alert_message}\n")
                                    f.write("-" * 66 + "\n\n")
                            
                            if not vuln_detected:
                                f.write(f"No vulnerabilities detected for {param_name} parameter\n\n")

                    # Advanced 핸들러 결과 저장
                    if 'advanced' in vulns:
                        for scan_type, adv_results in vulns['advanced'].items():
                            for result in adv_results:
                                if result.detected:
                                    f.write(f"handler: advanced\n")
                                    f.write(f"url: {self.target}\n")
                                    f.write(f"parameter: {param_name}\n")
                                    f.write(f"method: {self.method}\n")
                                    f.write(f"Detected: {result.detected}\n")
                                    f.write(f"Detail_Vuln: {scan_type}\n")
                                    f.write(f"payload: {result.payload}\n")
                                    f.write(f"Confidence: {result.confidence}\n")
                                    f.write(f"Evidence: {result.evidence}\n")
                                    if result.context:
                                        f.write(f"context: {result.context}\n")
                                    f.write("-" * 66 + "\n\n")

                # Final Arrange Result 저장
                f.write("Final Arrange Result\n")
                for param_name, vulns in results['vulnerabilities'].items():
                    if 'common' in vulns and 'advanced' in vulns:
                        common_result = vulns['common'][0]
                        advanced_result = vulns['advanced'].get('sqli_error_based', [])
                        
                        if common_result and advanced_result:
                            f.write(f"handler: common, advanced\n")
                            f.write(f"url: {self.target}\n")
                            f.write(f"parameter: {param_name}\n")
                            f.write(f"method: {self.method}\n")
                            
                            for vuln in common_result.vulnerabilities:
                                if vuln.detected:
                                    f.write(f"Type: {vuln.type}\n")
                                    f.write(f"Detected: {vuln.detected}\n")
                                    f.write(f"Detail_Vuln: Error-Based SQL Injection\n")
                                    f.write(f"Common_payload: {common_result.payload}\n")
                                    f.write(f"Common_Confidence: {vuln.confidence}\n")
                            
                            for adv_result in advanced_result:
                                if adv_result.detected:
                                    f.write(f"Advanced_payload: {adv_result.payload}\n")
                                    f.write(f"Advanced_Confidence: {adv_result.confidence}\n")
                            f.write("\n")
            
            self.logger.info(f"Results saved to {output_file}")
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")

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
                
                # 결과 출력 및 저장
                self._print_final_results(results)
                self._save_results(results)

            return results

        except Exception as e:
            self.logger.error(f"Controller execution error: {str(e)}")
            return {"parameters": [], "vulnerabilities": {}}


if __name__ == "__main__":
    async def main():
        # 파라미터 지정 테스트
        print("\n[*] Parameter Specification Test")
        print("-" * 50)
        controller = Controller(
            target="http://localhost/login.php",
            method="POST",
            param=["name", "password"]
        )
        results = await controller.async_run()
        
        # 파라미터 자동 탐지 테스트
        # print("\n[*] Parameter Reconnaissance Test")
        # print("-" * 50)
        # controller = Controller(
        #     target="http://localhost/login.php",
        #     recon_param=True
        # )
        # results = await controller.async_run()

        # 결과 출력
        print("\n[*] Final Results")
        print("-" * 50)
        print(f"Parameters found: {len(results['parameters'])}")
        print("\nVulnerabilities:")
        for param_name, vulns in results['vulnerabilities'].items():
            print(f"\nParameter: {param_name}")
            if 'common' in vulns:
                print("Common Vulnerabilities:")
                for result in vulns['common']:
                    for v in result.vulnerabilities:
                        if v.detected:
                            print(f"- {v.type} (Confidence: {v.confidence}%)")
            
            if 'advanced' in vulns:
                print("Advanced Vulnerabilities:")
                for scan_type, adv_results in vulns['advanced'].items():
                    for adv_result in adv_results:
                        if adv_result.detected:
                            print(f"- {scan_type} (Confidence: {adv_result.confidence}%)")

    asyncio.run(main())
