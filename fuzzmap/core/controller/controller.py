import json #테스트용 
from typing import Dict, List, Optional #테스트용 

import asyncio
from fuzzmap.core.handler.param_recon import ParamReconHandler
from fuzzmap.core.handler.common_payload import CommonPayloadHandler
from fuzzmap.core.handler.advanced_payload import AdvancedPayloadHandler
from fuzzmap.core.logging.log import Logger

class Controller:
    def __init__(self, target: str, method: str = "GET", 
                 param: Optional[List[str]] = None, 
                 recon_param: bool = False):
        self.target = target
        self.method = method.upper()
        self.params = param if param else []
        self.recon_param = recon_param
        self.logger = Logger()
        
        # 모든 설정을 Controller에서 관리
        self.config = {
            "timeout": 30,
            "deep_scan_threshold": 50
        }

    async def run(self) -> Dict:
        try:
            # 1. 파라미터 수집 
            if self.recon_param:
                param_handler = ParamReconHandler(self.target)
                collected_params = await param_handler.collect_parameters()
                
                self.logger.info(f"수집된 총 파라미터 수: {len(collected_params)}")
                for param in collected_params:
                    self.logger.info(f"Parameter - Name: {param.name}, Type: {param.param_type}, Method: {param.method}")

                if collected_params:
                    self.params = [param.name for param in collected_params]
                else:
                    self.logger.warning("파라미터를 찾을 수 없습니다.")
                    return {}
            elif not self.params:
                self.logger.error("파라미터가 지정되지 않았습니다.")
                return {}

            # 2. 공통 페이로드 테스트
            common_handler = CommonPayloadHandler(timeout=self.config["timeout"])  # timeout만 전달
            common_results = {}
            
            for param in self.params:
                result = await common_handler.scan(
                    url=self.target,
                    param_name=param,
                    param_type=self.method
                )
                common_results[param] = result
            
            # 결과가 비어있는지 확인
            if not common_results:
                self.logger.warning("취약점 스캔 결과가 없습니다.")
            
            # 3. 심화 스캔 대상 식별 (threshold 기반 판단을 여기서 수행)
            advanced_results = {}
            advanced_targets = []
            
            for param, results in common_results.items():
                for scan_result in results.get("scan_results", []):
                    for vuln in scan_result["payload_info"]["vulnerabilities"]:
                        # confidence 값이 threshold를 넘는지 여기서 확인
                        if vuln.get("confidence", 0) >= self.config["deep_scan_threshold"]:
                            advanced_targets.append({
                                "param": param,
                                "vuln_type": vuln["type"],
                                "confidence": vuln.get("confidence", 0)
                            })
            
            if advanced_targets:
                advanced_handler = AdvancedPayloadHandler()
                # 심화 스캔 구현 시 추가필요
                
            return {
                "common": common_results,
                "advanced": advanced_results
            }
            
        except Exception as e:
            self.logger.error(f"컨트롤러 실행 중 오류 발생: {str(e)}")
            return {}

"""테스트용"""
if __name__ == "__main__":
    async def main():
        #테스트 1 
        controller = Controller(
            target="http://php.testinvicti.com/artist.php",
            method="GET",
            param=["artist", "id"]
        )
        results = await controller.run()
        print("\n[+] Manual Parameter Scan Results:")
        print(json.dumps(results, indent=2))

        #테스트 2: 자동 파라미터 수집 테스트
        controller = Controller(
            target="http://php.testinvicti.com/artist.php",  
            recon_param=True  # 자동 파라미터 수집 활성화
        )
        results = await controller.run()
        print("\n[+] Auto Parameter Scan Results:")
        print(json.dumps(results, indent=2))

    asyncio.run(main())