from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from fuzzmap.core.handler.param_recon import ParamReconHandler, Param
from fuzzmap.core.handler.common_payload import CommonPayloadHandler, ScanResult
from fuzzmap.core.handler.advanced_payload import AdvancedPayloadHandler, Vuln, DetailVuln
from fuzzmap.core.logging.log import Logger
from fuzzmap.core.util.util import Util
import asyncio


@dataclass
class Vulnerability:
    """취약점 정보를 담는 클래스"""
    type: str
    pattern_type: str
    detected: bool = False
    confidence: int = 0
    evidence: str = ""


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
        self.params = param if param else []
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
        """개별 파라미터 스캔"""
        try:
            async with self.semaphore:
                target_url = Util.combine_url_with_path(param.url, param.path)
                
                # 모든 파라미터를 포함하도록 수정
                params = {}
                for p in self.params:
                    params[p] = ""
                
                scan_results = await self.common_payload.scan(
                    url=target_url,
                    params=params,  # 전체 파라미터 전달
                    method=param.method
                )
                
                if scan_results:
                    # common 결과 실시간 출력
                    self._print_scan_results(
                        "common", 
                        target_url, 
                        param.name,  # 현재 검사 중인 파라미터 이름
                        param.method, 
                        scan_results
                    )
                    
                    # 결과 파일 저장
                    self._save_results({
                        "vulnerabilities": {
                            param.name: {
                                "common": scan_results
                            }
                        }
                    }, "scan_results.txt")
                    
                return scan_results
                
        except Exception as e:
            self.logger.error(f"Parameter scan error - {param.name}: {str(e)}")
            return None

    async def _advanced_scan_parameter(self, param: Param, initial_results: List[ScanResult]) -> Dict:
        """개별 파라미터 심화 스캔"""
        advanced_results = {}
        try:
            target_url = Util.combine_url_with_path(param.url, param.path)
            
            # 모든 파라미터를 포함하도록 수정
            params = {}
            for p in self.params:
                params[p] = ""

            for result in initial_results:
                for vuln in result.vulnerabilities:
                    if vuln.detected and vuln.type == "sql_injection":
                        patterns = {
                            "error_based": DetailVuln.ERROR_BASED_SQLI.value,
                            "time_based": DetailVuln.TIME_BASED_SQLI.value,
                            "boolean_based": DetailVuln.BOOLEAN_BASED_SQLI.value
                        }
                        
                        for pattern_name, pattern_value in patterns.items():
                            advanced_handler = AdvancedPayloadHandler(
                                vuln=Vuln.SQLI,
                                pattern=pattern_value,
                                url=target_url,
                                method=param.method,
                                params=params  # 전체 파라미터 전달
                            )
                            results = await advanced_handler.run()
                            if results and any(r.detected for r in results):
                                advanced_results[pattern_name] = results
                                self._print_scan_results(
                                    "advanced", 
                                    target_url, 
                                    param.name,  # 현재 검사 중인 파라미터 이름
                                    param.method, 
                                    results
                                )

            # 결과 파일 저장
            if advanced_results:
                self._save_results({
                    "vulnerabilities": {
                        param.name: {  # 현재 검사 중인 파라미터 이름
                            "advanced": advanced_results
                        }
                    }
                }, "scan_results.txt")

            return advanced_results

        except Exception as e:
            self.logger.error(f"Advanced scan error - {param.name}: {str(e)}")
            return advanced_results

    async def _scan_vulnerabilities(self, params: List[Param]) -> Dict:
        """취약점 스캔 실행"""
        vulnerabilities = {}
        try:
            # 모든 파라미터를 한 번에 처리
            all_params = {param.name: "" for param in params}
            target_url = Util.combine_url_with_path(params[0].url, params[0].path)
            
            # 공통 스캔 한 번에 실행
            common_results = await self.common_payload.scan(
                url=target_url,
                params=all_params,
                method=params[0].method
            )
            
            if common_results:
                # 결과를 파라미터별로 정리하고 한 번만 출력
                self._print_scan_results(
                    "common",
                    target_url,
                    all_params,  # 전체 파라미터 전달
                    params[0].method,
                    common_results
                )
                
                # SQL Injection이 발견된 경우 심화 스캔 실행
                advanced_results = {}
                for result in common_results:
                    for vuln in result.vulnerabilities:
                        if vuln.detected and vuln.type == "sql_injection":
                            advanced_results = await self._advanced_scan(
                                target_url,
                                all_params,
                                params[0].method
                            )
                            break
                    if advanced_results:
                        break
                
                # 결과 저장
                for param in params:
                    vulnerabilities[param.name] = {
                        "common": common_results
                    }
                    if advanced_results:
                        vulnerabilities[param.name]["advanced"] = advanced_results
            
            return vulnerabilities
                
        except Exception as e:
            self.logger.error(f"Vulnerability scan error: {str(e)}")
            return vulnerabilities

    async def _advanced_scan(self, url: str, params: Dict[str, str], method: str) -> Dict:
        """심화 스캔 실행"""
        advanced_results = {}
        try:
            patterns = {
                "error_based": DetailVuln.ERROR_BASED_SQLI.value,
                "time_based": DetailVuln.TIME_BASED_SQLI.value,
                "boolean_based": DetailVuln.BOOLEAN_BASED_SQLI.value
            }
            
            for pattern_name, pattern_value in patterns.items():
                advanced_handler = AdvancedPayloadHandler(
                    vuln=Vuln.SQLI,
                    pattern=pattern_value,
                    url=url,
                    method=method,
                    params=params
                )
                results = await advanced_handler.run()
                if results and any(r.detected for r in results):
                    advanced_results[pattern_name] = results
                    # 심화 스캔 결과도 한 번만 출력
                    self._print_scan_results(
                        "advanced",
                        url,
                        params,  # 전체 파라미터 전달
                        method,
                        results
                    )
            
            return advanced_results
            
        except Exception as e:
            self.logger.error(f"Advanced scan error: {str(e)}")
            return advanced_results

    def _print_scan_results(self, handler: str, url: str, params: Dict[str, str], 
                           method: str, scan_results: List[ScanResult]) -> None:
        """스캔 결과 출력"""
        for result in scan_results:
            if handler == "common":
                self._print_common_result(url, params, method, result)
            elif handler == "advanced":
                self._print_advanced_result(url, params, method, result)

    def _print_common_result(self, url: str, params: Dict[str, str], 
                            method: str, result: ScanResult) -> None:
        """공통 페이로드 결과 출력"""
        for vuln in result.vulnerabilities:
            if not vuln.detected:
                continue
            
            print("\nhandler: common")
            print(f"url: {url}")
            print(f"parameters: {list(params.keys())}")  # 모든 파라미터 표시
            print(f"method: {method}")
            print(f"Type: {vuln.type}")
            print(f"Pattern_Type: {vuln.pattern_type}")
            print(f"payload: {result.payload}")
            print(f"Confidence: {vuln.confidence}")
            print(f"Evidence: {vuln.evidence}")
            self._print_response_info(result)
            self._print_alert_info(result)
            print("-" * 66)

    def _print_advanced_result(self, url: str, params: Dict[str, str], 
                              method: str, result: ScanResult) -> None:
        """심화 페이로드 결과 출력"""
        if not result.detected:
            return
        
        print("\nhandler: advanced")
        print(f"url: {url}")
        print(f"parameters: {list(params.keys())}")  # 모든 파라미터 표시
        print(f"method: {method}")
        print(f"Detail_Vuln: {result.detailvuln}")
        print(f"payload: {result.payload}")
        print(f"Confidence: {result.confidence}")
        print(f"Evidence: {result.evidence}")
        if result.context:
            print(f"Context: {result.context}")
        print("-" * 66)

    def _print_response_info(self, result: ScanResult) -> None:
        """응답 정보 출력"""
        if isinstance(result.response_time, (int, float)):
            print(f"Response_Time: {result.response_time:.2f}s")
        elif isinstance(result.response_time, list):
            print(f"Response_Times: {[f'{t:.2f}s' for t in result.response_time]}")
        
        if isinstance(result.response_length, int):
            print(f"Response_Length: {result.response_length}")
        elif isinstance(result.response_length, list):
            print(f"Response_Lengths: {result.response_length}")

    def _print_alert_info(self, result: ScanResult) -> None:
        """알림 정보 출력"""
        if hasattr(result, 'alert_triggered') and result.alert_triggered:
            print(f"Alert_Triggered: {result.alert_triggered}")
            if result.alert_message:
                print(f"Alert_Message: {result.alert_message}")

    def _print_final_results(self, results: Dict) -> None:
        """최종 결과 출력"""
        print("\nFinal Arrange Result")
        
        if not results.get('vulnerabilities'):
            print("No vulnerabilities detected")
            return
        
        # 모든 파라미터를 한 번에 처리
        all_params = list(results['vulnerabilities'].keys())
        
        # 첫 번째 파라미터의 결과를 기준으로 출력 (동일한 결과이므로)
        first_param = all_params[0]
        param_results = results['vulnerabilities'][first_param]
        
        common_results = param_results.get('common', [])
        advanced_results = param_results.get('advanced', {})
        
        for common_result in common_results:
            for vuln in common_result.vulnerabilities:
                if vuln.detected:
                    print(f"\nhandler: common, advanced")
                    print(f"url: {self.target}")
                    print(f"parameters: {all_params}")  # 모든 파라미터 표시
                    print(f"method: {self.method}")
                    print(f"Type: {vuln.type}")
                    print(f"Detected: True")
                    print(f"Common_payload: {common_result.payload}")
                    print(f"Common_Confidence: {vuln.confidence}")
                    
                    # Advanced 결과 출력
                    if advanced_results:
                        for pattern_type, adv_results in advanced_results.items():
                            for adv_result in adv_results:
                                if adv_result.detected:
                                    print(f"Detail_Vuln: {adv_result.detailvuln}")
                                    print(f"Advanced_payload: {adv_result.payload}")
                                    print(f"Advanced_Confidence: {adv_result.confidence}")
                                    if adv_result.context:
                                        print(f"Context: {adv_result.context}")
                    print("-" * 66)

    def _save_results(self, results: Dict, output_file: str = "scan_results.txt") -> None:
        """
        스캔 결과 파일 저장
        Args:
            results: 저장할 결과 딕셔너리
            output_file: 저장할 파일 경로
        """
        try:
            with open(output_file, 'w') as f:
                self._save_handler_results(results, f)
                self._save_final_results(results, f)
                self.logger.info(f"Results appended to {output_file}")
                
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")

    def _save_handler_results(self, results: Dict, file_obj) -> None:
        """핸들러 결과 저장"""
        # 모든 파라미터를 한 번에 처리
        all_params = list(results['vulnerabilities'].keys())
        
        # 첫 번째 파라미터의 결과만 저장 (동일한 결과이므로)
        first_param = all_params[0]
        vulns = results['vulnerabilities'][first_param]
        
        if 'common' in vulns:
            self._save_common_results(all_params, vulns['common'], file_obj)
        if 'advanced' in vulns:
            self._save_advanced_results(all_params, vulns['advanced'], file_obj)

    def _save_common_results(self, params: List[str], common_results: List, 
                            file_obj) -> None:
        """공통 페이로드 결과 저장"""
        for result in common_results:
            for vuln in result.vulnerabilities:
                if not vuln.detected:
                    continue
                    
                file_obj.write("\nhandler: common\n")
                file_obj.write(f"url: {self.target}\n")
                file_obj.write(f"parameters: {params}\n")  # 모든 파라미터 표시
                file_obj.write(f"method: {self.method}\n")
                file_obj.write(f"Type: {vuln.type}\n")
                file_obj.write(f"Pattern_Type: {vuln.pattern_type}\n")
                file_obj.write(f"payload: {result.payload}\n")
                file_obj.write(f"Confidence: {vuln.confidence}\n")
                file_obj.write(f"Evidence: {vuln.evidence}\n")
                self._write_response_info(result, file_obj)
                self._write_alert_info(result, file_obj)
                file_obj.write("-" * 66 + "\n\n")

    def _save_advanced_results(self, params: List[str], advanced_results: Dict, 
                              file_obj) -> None:
        """심화 페이로드 결과 저장"""
        for scan_type, results in advanced_results.items():
            for result in results:
                if not result.detected:
                    continue
                    
                file_obj.write("\nhandler: advanced\n")
                file_obj.write(f"url: {self.target}\n")
                file_obj.write(f"parameters: {params}\n")  # 모든 파라미터 표시
                file_obj.write(f"method: {self.method}\n")
                file_obj.write(f"Detail_Vuln: {result.detailvuln}\n")
                file_obj.write(f"payload: {result.payload}\n")
                file_obj.write(f"Confidence: {result.confidence}\n")
                file_obj.write(f"Evidence: {result.evidence}\n")
                if result.context:
                    file_obj.write(f"Context: {result.context}\n")
                file_obj.write("-" * 66 + "\n\n")

    def _write_response_info(self, result: ScanResult, file_obj) -> None:
        """응답 정보 저장"""
        if isinstance(result.response_time, (int, float)):
            file_obj.write(f"Response_Time: {result.response_time:.2f}s\n")
        elif isinstance(result.response_time, list):
            file_obj.write(f"Response_Times: {[f'{t:.2f}s' for t in result.response_time]}\n")
        
        if isinstance(result.response_length, int):
            file_obj.write(f"Response_Length: {result.response_length}\n")
        elif isinstance(result.response_length, list):
            file_obj.write(f"Response_Lengths: {result.response_length}\n")

    def _write_alert_info(self, result: ScanResult, file_obj) -> None:
        """알림 정보 저장"""
        if hasattr(result, 'alert_triggered') and result.alert_triggered:
            file_obj.write(f"Alert_Triggered: {result.alert_triggered}\n")
            if result.alert_message:
                file_obj.write(f"Alert_Message: {result.alert_message}\n")

    def _write_advanced_info(self, result: ScanResult, file_obj) -> None:
        """심화 정보 저장"""
        file_obj.write(f"Detected: {result.detected}\n")
        file_obj.write(f"Detail_Vuln: {result.detailvuln}\n")
        file_obj.write(f"payload: {result.payload}\n")
        file_obj.write(f"Confidence: {result.confidence}\n")
        file_obj.write(f"Evidence: {result.evidence}\n")
        if result.context:
            file_obj.write(f"context: {result.context}\n")

    def _save_final_results(self, results: Dict, file_obj) -> None:
        """최종 결과 저장"""
        file_obj.write("\nFinal Arrange Result\n")
        
        if not results.get('vulnerabilities'):
            file_obj.write("No vulnerabilities detected\n")
            return
        
        # 모든 파라미터를 한 번에 처리
        all_params = list(results['vulnerabilities'].keys())
        
        # 첫 번째 파라미터의 결과를 기준으로 저장
        first_param = all_params[0]
        param_results = results['vulnerabilities'][first_param]
        
        common_results = param_results.get('common', [])
        advanced_results = param_results.get('advanced', {})
        
        for common_result in common_results:
            for vuln in common_result.vulnerabilities:
                if vuln.detected:
                    file_obj.write(f"\nhandler: common, advanced\n")
                    file_obj.write(f"url: {self.target}\n")
                    file_obj.write(f"parameters: {all_params}\n")  # 모든 파라미터 표시
                    file_obj.write(f"method: {self.method}\n")
                    file_obj.write(f"Type: {vuln.type}\n")
                    file_obj.write(f"Detected: True\n")
                    file_obj.write(f"Common_payload: {common_result.payload}\n")
                    file_obj.write(f"Common_Confidence: {vuln.confidence}\n")
                    
                    # Advanced 결과 저장
                    if advanced_results:
                        for pattern_type, adv_results in advanced_results.items():
                            for adv_result in adv_results:
                                if adv_result.detected:
                                    file_obj.write(f"Detail_Vuln: {adv_result.detailvuln}\n")
                                    file_obj.write(f"Advanced_payload: {adv_result.payload}\n")
                                    file_obj.write(f"Advanced_Confidence: {adv_result.confidence}\n")
                                    if adv_result.context:
                                        file_obj.write(f"Context: {adv_result.context}\n")
                    file_obj.write("-" * 66 + "\n")

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
