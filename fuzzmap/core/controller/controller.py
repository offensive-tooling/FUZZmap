import json
from typing import Dict, List, Optional
import asyncio

from fuzzmap.core.handler.param_recon import ParamReconHandler
from fuzzmap.core.handler.common_payload import CommonPayloadHandler
from fuzzmap.core.handler.advanced_payload import AdvancedPayloadHandler
from fuzzmap.core.handler.payload_request import RequestPayloadHandler
from fuzzmap.core.handler.payload_request import Logger


class Controller:
    def __init__(self, target_url: str, method: str = "GET", 
                 params: List[str] = None, recon_param: bool = False):
        self.url = target_url
        self.method = method.upper()
        self.params = params or []
        self.recon_param = recon_param
        self.logger = Logger()

    async def run(self):
        try:
            handler = CommonPayloadHandler()
            params_dict = {}

            # 1. 파라미터 수집 및 전처리
            if self.recon_param:
                # 1-1. ParamRecon 모듈로 파라미터 자동 수집
                collected = await ParamReconHandler(self.url).collect_parameters()
                if not collected:
                    self.logger.warning("No parameters found")
                    return {}

                # 1-2. 수집된 파라미터를 endpoint별로 정리
                for param in collected:
                    # URL과 path 결합하여 최종 endpoint URL 생성
                    endpoint_url = param.url.rstrip('/') + (param.path or '')
                    # endpoint별 파라미터 딕셔너리에 추가
                    params_dict.setdefault(endpoint_url, {})[param.name] = ""
            else:
                # 1-3. 수동 지정된 파라미터 처리
                if not self.params:
                    self.logger.error("No parameters specified")
                    return {}
                params_dict = {self.url: {p: "" for p in self.params}}

            # 2. CommonPayloadHandler로 취약점 스캔 실행
            results = {}
            for url, params in params_dict.items():
                # 각 endpoint URL과 파라미터에 대해 스캔 수행
                results[url] = await handler.scan(url=url, params=params)

            return results

        except Exception as e:
            self.logger.error(f"Error in controller: {str(e)}")
            return {}

"""테스트"""
if __name__ == "__main__":
   import asyncio
  
   async def test():
       # 수동 파라미터 테스트
       ctrl = Controller(
           target_url="http://php.testinvicti.com/artist.php",
           params=["artist", "id"]
       )
       results = await ctrl.run()
       print("Manual scan results:", results)

       # 자동 파라미터 테스트  
       auto_ctrl = Controller(
           target_url="https://ocw.mit.edu/",
           recon_param=True
       )
       auto_results = await auto_ctrl.run()
       print("\n\nAuto scan results:", auto_results)

   asyncio.run(test())