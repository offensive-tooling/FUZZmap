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
                 advanced: bool = False,
                 user_agent: Optional[str] = None,
                 cookies: Optional[Dict[str, str]] = None,
                 max_concurrent: int = 10):
        """
        컨트롤러 초기화
        Args:
            target: 대상 URL
            method: HTTP 메서드 (GET/POST)
            param: 수동으로 지정된 파라미터 목록
            recon_param: 파라미터 자동 수집 여부
            advanced: 심화 페이로드 스캔 여부
            user_agent: 사용자 정의 User-Agent
            cookies: 요청에 포함할 쿠키
            max_concurrent: 최대 동시 실행 수
        """
        self.target = target
        self.method = method.upper()
        self.params = param if param else []
        self.recon_param = recon_param
        self.advanced = advanced
        self.user_agent = user_agent
        self.cookies = cookies
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
                    method=param.method,
                    user_agent=self.user_agent,
                    cookies=self.cookies
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
        
        # 심화 스캔 옵션이 활성화되지 않은 경우 빈 결과 반환
        if not self.advanced:
            return advanced_results
            
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
                                params=params,  # 전체 파라미터 전달
                                user_agent=self.user_agent,
                                cookies=self.cookies
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
                    
                    # XSS 취약점 처리 (elif가 아닌 if로 변경하여 독립적으로 처리)
                    if vuln.detected and vuln.type == "xss":
                        advanced_handler = AdvancedPayloadHandler(
                            vuln=Vuln.XSS,
                            pattern=DetailVuln.XSS.value,
                            url=target_url,
                            method=param.method,
                            params=params,
                            user_agent=self.user_agent,
                            cookies=self.cookies
                        )
                        results = await advanced_handler.run()
                        if results and any(r.detected for r in results):
                            advanced_results["xss"] = results
                            self._print_scan_results(
                                "advanced", 
                                target_url, 
                                param.name,
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
                method=params[0].method,
                user_agent=self.user_agent,
                cookies=self.cookies
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
                
                # 심화 스캔 옵션이 활성화된 경우 심화 스캔 실행
                advanced_results = {}
                if self.advanced:
                    for result in common_results:
                        for vuln in result.vulnerabilities:
                            # SQL Injection 취약점 심화 스캔
                            if vuln.detected and vuln.type == "sql_injection":
                                sql_results = await self._advanced_scan(
                                    target_url,
                                    all_params,
                                    params[0].method,
                                    vuln_type="sql_injection"
                                )
                                if sql_results:
                                    advanced_results.update(sql_results)
                            
                            # XSS 취약점 심화 스캔 (elif가 아닌 if로 변경)
                            if vuln.detected and vuln.type == "xss":
                                xss_results = await self._advanced_scan(
                                    target_url,
                                    all_params,
                                    params[0].method,
                                    vuln_type="xss"
                                )
                                if xss_results:
                                    advanced_results.update(xss_results)
            
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

    async def _advanced_scan(self, url: str, params: Dict[str, str], method: str, vuln_type: str = "sql_injection") -> Dict:
        """심화 스캔 실행"""
        advanced_results = {}
        
        # 심화 스캔 옵션이 활성화되지 않은 경우 빈 결과 반환
        if not self.advanced:
            return advanced_results
            
        try:
            if vuln_type == "sql_injection":
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
                        params=params,
                        user_agent=self.user_agent,
                        cookies=self.cookies
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
            
            elif vuln_type == "xss":
                advanced_handler = AdvancedPayloadHandler(
                    vuln=Vuln.XSS,
                    pattern=DetailVuln.XSS.value,
                    url=url,
                    method=method,
                    params=params,
                    user_agent=self.user_agent,
                    cookies=self.cookies
                )
                results = await advanced_handler.run()
                if results and any(r.detected for r in results):
                    advanced_results["xss"] = results
                    # 심화 스캔 결과 출력
                    self._print_scan_results(
                        "advanced",
                        url,
                        params,
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
            
            print("\n\033[94mhandler: common\033[0m")
            print(f"\033[97murl:\033[0m \033[94m{url}\033[0m")
            print(f"\033[97mparameters:\033[0m \033[94m{list(params.keys())}\033[0m")  # 모든 파라미터 표시
            print(f"\033[97mmethod: {method}\033[0m")
            print(f"\033[91mType:\033[0m \033[97m{vuln.type}\033[0m")
            print(f"\033[91mPattern_Type:\033[0m \033[97m{vuln.pattern_type}\033[0m")
            print(f"\033[93mpayload:\033[0m \033[97m{result.payload}\033[0m")
            print(f"\033[92mConfidence: {vuln.confidence}\033[0m")
            print(f"\033[93mEvidence:\033[0m \033[97m{vuln.evidence}\033[0m")
            self._print_response_info(result)
            self._print_alert_info(result)
            print("\033[90m" + "-" * 66 + "\033[0m")

    def _print_advanced_result(self, url: str, params: Dict[str, str], 
                              method: str, result: ScanResult) -> None:
        """심화 페이로드 결과 출력"""
        if not result.detected:
            return
        
        print("\n\033[95mhandler: advanced\033[0m")
        print(f"\033[97murl:\033[0m \033[95m{url}\033[0m")
        print(f"\033[97mparameters:\033[0m \033[95m{list(params.keys())}\033[0m")  # 모든 파라미터 표시
        print(f"\033[97mmethod: {method}\033[0m")
        print(f"\033[91mDetail_Vuln:\033[0m \033[97m{result.detailvuln}\033[0m")
        print(f"\033[93mpayload:\033[0m \033[97m{result.payload}\033[0m")
        print(f"\033[92mConfidence: {result.confidence}\033[0m")
        print(f"\033[91mEvidence:\033[0m \033[97m{result.evidence}\033[0m")
        if result.context:
            print(f"\033[97mContext: {result.context}\033[0m")
        print("\033[90m" + "-" * 66 + "\033[0m")

    def _print_response_info(self, result: ScanResult) -> None:
        """응답 정보 출력"""
        if isinstance(result.response_time, (int, float)):
            print(f"\033[97mResponse_Time: {result.response_time:.2f}s\033[0m")
        elif isinstance(result.response_time, list):
            print(f"\033[97mResponse_Times: {[f'{t:.2f}s' for t in result.response_time]}\033[0m")
        
        if isinstance(result.response_length, int):
            print(f"\033[97mResponse_Length: {result.response_length}\033[0m")
        elif isinstance(result.response_length, list):
            print(f"\033[97mResponse_Lengths: {result.response_length}\033[0m")

    def _print_alert_info(self, result: ScanResult) -> None:
        """알림 정보 출력"""
        if hasattr(result, 'dialog_triggered') and result.dialog_triggered:
            print(f"\033[93mDialog_Triggered: {result.dialog_triggered}\033[0m")
            if result.dialog_type:
                print(f"\033[93mDialog_Type: {result.dialog_type}\033[0m")
            if result.dialog_message:
                print(f"\033[93mDialog_Message: {result.dialog_message}\033[0m")

    def _print_final_results(self, results: Dict) -> None:
        """최종 결과 출력"""
        print("\n\033[96mFinal Arrange Result 😊\033[0m")
        
        if not results.get('vulnerabilities'):
            print("\033[91mNo vulnerabilities detected 😭\033[0m")
            return
        
        # 모든 파라미터를 한 번에 처리
        all_params = list(results['vulnerabilities'].keys())
        
        # 첫 번째 파라미터의 결과를 기준으로 출력
        first_param = all_params[0]
        param_results = results['vulnerabilities'][first_param]
        
        common_results = param_results.get('common', [])
        advanced_results = param_results.get('advanced', {})
        
        for common_result in common_results:
            for vuln in common_result.vulnerabilities:
                if vuln.detected:
                    print(f"\n\033[97mhandler:\033[0m \033[94mcommon\033[0m\033[97m,\033[0m \033[95madvanced\033[0m")
                    print(f"🎯 \033[97murl: {self.target}\033[0m")
                    print(f"\033[97mparameters: {all_params}\033[0m")  # 모든 파라미터 표시
                    print(f"\033[97mmethod: {self.method}\033[0m")
                    print(f"\033[91mType:\033[0m \033[97m{vuln.type}\033[0m")
                    print(f"💰 \033[91mDetected: True\033[0m")
                    print(f"\033[93mCommon_payload:\033[0m \033[97m{common_result.payload}\033[0m")
                    print(f"\033[92mCommon_Confidence: {vuln.confidence}\033[0m")
                    
                    # Advanced 결과 출력
                    if advanced_results:
                        for pattern_type, adv_results in advanced_results.items():
                            for adv_result in adv_results:
                                if adv_result.detected:
                                    print(f"🔍 \033[91mDetail_Vuln:\033[0m \033[97m{adv_result.detailvuln}\033[0m")
                                    print(f"\033[93mAdvanced_payload:\033[0m \033[97m{adv_result.payload}\033[0m")
                                    print(f"\033[92mAdvanced_Confidence: {adv_result.confidence}\033[0m")
                                    if adv_result.context:
                                        print(f"\033[97mContext: {adv_result.context}\033[0m")
                                    print(f"")
                    print("\033[90m" + "-" * 66 + "\033[0m")

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
        if hasattr(result, 'dialog_triggered') and result.dialog_triggered:
            file_obj.write(f"Dialog_Triggered: {result.dialog_triggered}\n")
            if result.dialog_type:
                file_obj.write(f"Dialog_Type: {result.dialog_type}\n")
            if result.dialog_message:
                file_obj.write(f"Dialog_Message: {result.dialog_message}\n")

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
                                    file_obj.write(f"")
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
                if self.advanced:
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
            #param=["name", "password", "db_type"] db select에 Payload가 포함되어 공격 진행 불가
        )
        results = await controller.async_run()
        print(f"-----> results1: {results}")
        
        # 파라미터 자동 탐지 테스트
        # print("\n[*] Parameter Reconnaissance Test")
        # print("-" * 50)
        # controller = Controller(
        #     target="http://localhost/login.php",
        #     recon_param=True
        # )
        # results = await controller.async_run()
        # print(f"-----> results2: {results}")

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
