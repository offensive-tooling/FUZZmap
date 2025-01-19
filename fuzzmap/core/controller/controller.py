from typing import Dict, List, Optional
from ..handler.param_recon import ParamRecon
from ..handler.common_payload import CommonPayload
from ..handler.advanced_payload import AdvancedPayload
from ..logging.log import Logger

class Controller:
    def __init__(self, target: str, method: str = "GET", 
                 param: Optional[List[str]] = None, 
                 recon_param: bool = False):
        self.target = target
        self.method = method.upper()
        self.params = param if param else []
        self.recon_param = recon_param
        self.logger = Logger()
        self.param_recon = ParamRecon()
        self.common_payload = CommonPayload()
        self.advanced_payload = AdvancedPayload()

    def run(self) -> Dict:
        try:
            # 파라미터 수집
            if self.recon_param:
                self.params = self.param_recon.collect(self.target)
            elif not self.params:
                self.logger.error("파라미터가 지정되지 않았습니다.")
                return {}

            # 공통 페이로드 테스트
            self.logger.info(f"공통 페이로드 테스트 시작 - 대상 URL: {self.target}")
            common_results = self.common_payload.test(
                self.target, 
                self.params, 
                self.method
            )
            
            # 심화 페이로드 테스트
            advanced_results = self.advanced_payload.test(
                self.target, 
                self.params,
                self.method,
                common_results
            )
            
            return {
                "common": common_results,
                "advanced": advanced_results
            }
            
        except Exception as e:
            self.logger.error(f"컨트롤러 실행 중 오류 발생: {str(e)}")
            return {} 
        

@TODO
'''
1. ParamReconHandler url 값도 같이 출력되도록 처리
2. CommonPayload 리턴 값 확인
3. AdvancedPayload 리턴 값 확인
'''