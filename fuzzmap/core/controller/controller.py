import json #테스트용 
import asyncio #테스트용
from typing import Dict, List, Optional #테스트용 

from fuzzmap.core.handler.param_recon import ParamReconHandler
from fuzzmap.core.handler.common_payload import CommonPayloadHandler
from fuzzmap.core.handler.advanced_payload import AdvancedPayloadHandler
from fuzzmap.core.handler.payload_request import RequestPayloadHandler
from fuzzmap.core.handler.payload_request import Logger

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
        self.Logger = Logger()
        
        # 모듈 설정
        self.config = {
            "timeout": 30,
            "deep_scan_threshold": 50,
            "payload_files": ["common_payload.json", "sqli_payload.json"],
            "max_concurrent": 5
        }

    async def run(self) -> Dict:
        try:
            # 1. 파라미터 수집 단계
            if self.recon_param:
                param_handler = ParamReconHandler(self.target)
                collected_params = await param_handler.collect_parameters()
                
                if collected_params:
                    self.params = [param.name for param in collected_params]
                else:
                    self.Logger.warning("파라미터를 찾을 수 없습니다.")
                    return {}
            elif not self.params:
                self.Logger.error("파라미터가 지정되지 않았습니다.")
                return {}

            # 2. 페이로드 요청 핸들러 초기화 및 실행
            request_handler = RequestPayloadHandler(
                payload_files=self.config["payload_files"],
                timeout=self.config["timeout"],
                max_concurrent=self.config["max_concurrent"]
            )

            payload_results = {}
            for param in self.params:
                # 각 파라미터에 대해 페이로드 전송
                param_dict = {param: ""}  # 페이로드가 삽입될 파라미터
                scan_results = await request_handler.send_payloads(
                    url=self.target,
                    params=param_dict,
                    method=self.method
                )
                payload_results[param] = scan_results

            # 3. 공통 페이로드 분석 실행
            common_handler = CommonPayloadHandler(timeout=self.config["timeout"])
            common_results = {}
            
            for param, results in payload_results.items():
                # RequestPayloadHandler의 결과를 CommonPayloadHandler로 전달
                result = await common_handler.scan(
                    url=self.target,
                    param_name=param,
                    param_type=self.method
                )
                
                if result:
                    common_results[param] = result

            # 4. 심화 스캔 대상 식별
            advanced_results = {}
            advanced_targets = []
            
            for param, results in common_results.items():
                scan_results = results.get("scan_results", [])
                for scan_result in scan_results:
                    vulnerabilities = scan_result.get("payload_info", {}).get("vulnerabilities", [])
                    
                    for vuln in vulnerabilities:
                        # confidence 값이 threshold를 넘으면 심화 스캔 대상으로 선정
                        if vuln.get("confidence", 0) >= self.config["deep_scan_threshold"]:
                            advanced_targets.append({
                                "param": param,
                                "vuln_type": vuln["type"],
                                "confidence": vuln["confidence"],
                                "payload_info": scan_result["payload_info"]
                            })

            # 5. 심화 스캔 실행 (대상이 있는 경우)
            if advanced_targets:
                advanced_handler = AdvancedPayloadHandler()
                for target in advanced_targets:
                    advanced_result = await advanced_handler.scan(
                        url=self.target,
                        param_name=target["param"],
                        vuln_type=target["vuln_type"],
                        payload_info=target["payload_info"]
                    )
                    if advanced_result:
                        advanced_results[target["param"]] = advanced_result

            return {
                "payload_requests": payload_results,
                "common": common_results,
                "advanced": advanced_results
            }
            
        except Exception as e:
            self.Logger.error(f"컨트롤러 실행 중 오류 발생: {str(e)}")
            return {}

"""테스트"""
if __name__ == "__main__":
   import os
   async def main():
       # 현재 스크립트 경로 가져오기
       current_dir = os.path.dirname(os.path.abspath(__file__))
       output_dir = os.path.join(current_dir, "responses")
       os.makedirs(output_dir, exist_ok=True)

       # 수동 파라미터 테스트
       manual_controller = Controller(
           target="http://php.testinvicti.com/artist.php",
           method="GET",
           param=["artist", "id"]
       )
       manual_results = await manual_controller.run()
       
       # 결과 저장
       manual_output_file = os.path.join(output_dir, "manual_scan_results.json")
       try:
           with open(manual_output_file, "w", encoding="utf-8") as f:
               json.dump(manual_results, f, indent=4, ensure_ascii=False)
           print(f"수동 스캔 결과가 저장되었습니다: {manual_output_file}")
       except Exception as e:
           print(f"수동 스캔 결과 저장 실패: {e}")

       # 자동 파라미터 수집 테스트
       auto_controller = Controller(
           target="http://php.testinvicti.com/artist.php",
           recon_param=True
       )
       auto_results = await auto_controller.run()

       # 결과 저장
       auto_output_file = os.path.join(output_dir, "auto_scan_results.json")
       try:
           with open(auto_output_file, "w", encoding="utf-8") as f:
               json.dump(auto_results, f, indent=4, ensure_ascii=False)
           print(f"자동 스캔 결과가 저장되었습니다: {auto_output_file}")
       except Exception as e:
           print(f"자동 스캔 결과 저장 실패: {e}")

   asyncio.run(main())