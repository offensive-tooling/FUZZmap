import sys
import os
import asyncio
import json
import time
from typing import Any, Dict, List, Optional

import aiohttp
from playwright.async_api import async_playwright, Dialog, Response

from fuzzmap.core.util.util import Util 
from fuzzmap.core.logging.log import Logger  


class RequestPayloadHandler:
    """
    - "vulnerabilities"에 { "type": "xss" }가 있는 경우 Playwright로 alert() 검사
    - 그렇지 않으면 기존 aiohttp 방식으로 HTTP 요청
    - 'payload'가 list이든 단일 값이든 일관되게 처리
    - 에러(Timeout, ClientError) 시 status=-1, response_text에 에러 표시
    """

    def __init__(self, payload_files: Optional[List[str]] = None, timeout: float = 10.0, max_concurrent: int = 5) -> None:
        """
        초기화 메서드.

        Args:
            payload_files (Optional[List[str]]): 로드할 페이로드 JSON 파일 이름 목록.
            timeout (float): 요청 타임아웃 (초).
            max_concurrent (int): Playwright 태스크의 최대 동시성 제한.
        """
        self.common_payloads: List[Dict[str, Any]] = []
        self.responses: List[Dict[str, Any]] = []
        self.timeout: float = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)  # 동시성 제한
        self.final_results: List[Dict[str, Any]] = []  # final_results 초기화
        self.playwright = None  # Playwright 인스턴스
        self.browser = None  # 브라우저 인스턴스
        self.context = None  # 브라우저 컨텍스트
        self._logger = Logger()  # Logger 인스턴스 초기화

        if payload_files:
            for payload_file in payload_files:
                self.load_payloads(payload_file)

    async def initialize_playwright(self) -> None:
        """
        Playwright와 브라우저 인스턴스를 초기화합니다.
        """
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=True)
        self.context = await self.browser.new_context()
        
        # 불필요한 리소스 차단 (이미지, CSS, 폰트 등)
        await self.context.route("**/*.{png,jpg,jpeg,gif,svg,css,woff,woff2}", lambda route: asyncio.create_task(route.abort()))
        self._logger.info("Playwright 초기화 및 불필요한 리소스 차단 설정 완료.")

    async def close_playwright(self) -> None:
        """
        Playwright와 브라우저 인스턴스를 종료합니다.
        """
        if self.context:
            await self.context.close()
            self._logger.info("브라우저 컨텍스트 종료.")
        if self.browser:
            await self.browser.close()
            self._logger.info("브라우저 종료.")
        if self.playwright:
            await self.playwright.stop()
            self._logger.info("Playwright 인스턴스 종료.")

    def load_payloads(self, payload_file: str = "common_payload.json") -> None:
        """
        지정된 JSON 파일에서 페이로드를 로드합니다.

        Args:
            payload_file (str): payloads 디렉토리 내의 JSON 파일 이름.
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        json_path = os.path.join(script_dir, "payloads", payload_file)

        self._logger.debug(f"JSON 경로 = {json_path}")
        try:
            with open(json_path, "r", encoding="utf-8") as file:
                data = json.load(file)
        except Exception as error:
            self._logger.error(f"JSON 로드 실패: {error}")
            return

        self.common_payloads.extend(data.get("payloads", []))
        self._logger.info(f"=== 로드된 페이로드 ({payload_file}) ===")
        self._logger.info(json.dumps(data.get("payloads", []), indent=4, ensure_ascii=False))
        self._logger.info(f"총 페이로드 수: {len(self.common_payloads)}")

    async def send_payloads(
        self,
        url: str,
        params: Dict[str, str],
        method: str = "GET"
    ) -> List[Dict[str, Any]]:
        """
        common_payloads 내 각 항목을 처리:
         - 'vulnerabilities'에 "xss"가 있는지 확인
         - 있으면 Playwright로 XSS 검사 (alert_triggered, alert_message, response_text, status_code)
         - 없으면 aiohttp로 기존 HTTP 요청
         - 'payload'가 list이든 단일 값이든 일관되게 처리

        Args:
            url (str): 요청할 URL.
            params (Dict[str, str]): 요청 파라미터.
            method (str): HTTP 메서드 (GET, POST 등).

        Returns:
            List[Dict[str, Any]]: 그룹화된 최종 결과 리스트.
        """
        await self.initialize_playwright()

        tasks: List[asyncio.Task] = []
        payload_tasks_map: List[Dict[str, Any]] = []  # 각 태스크가 어떤 payload_info에 속하는지 추적

        playwright_task_args = []

        for item in self.common_payloads:
            vulnerabilities = item.get("vulnerabilities", [])
            has_xss = any(vuln.get("type") == "xss" for vuln in vulnerabilities)

            payload_field = item.get("payload", [])
            if not isinstance(payload_field, list):
                payload_field = [payload_field]

            for payload_value in payload_field:
                # 파라미터 준비: 고정값과 페이로드 값
                current_params = {
                    key: (payload_value if value == "" else value)
                    for key, value in params.items()
                }

                if has_xss:
                    playwright_task_args.append((url, current_params, method, item))
                else:
                    task = asyncio.create_task(
                        self._send_single_payload_aiohttp(url, current_params, method, item)
                    )
                    tasks.append(task)
                    payload_tasks_map.append(item)

        # Playwright 기반 태스크 처리
        if playwright_task_args:
            async def playwright_task(url, current_params, method, item):
                start_time = time.time()
                alert_triggered = False
                alert_message = ""
                status_code: Optional[int] = None
                response_text = ""
                final_url = ""

                try:
                    page = await self.context.new_page()

                    # 네트워크 응답 핸들러
                    captured_response: Optional[Response] = None

                    async def handle_response(response: Response):
                        nonlocal captured_response
                        if response.url == final_url:
                            captured_response = response

                    page.on("response", handle_response)

                    # dialog 이벤트 핸들러
                    async def handle_dialog(dialog: Dialog):
                        nonlocal alert_triggered, alert_message
                        if dialog.type == "alert":
                            alert_triggered = True
                            alert_message = dialog.message
                        await dialog.dismiss()

                    page.on("dialog", handle_dialog)

                    # 랜덤 User-Agent 설정
                    random_user_agent = Util.get_random_user_agent()
                    await page.set_extra_http_headers({"User-Agent": random_user_agent})
                    self._logger.debug(f"Set User-Agent to: {random_user_agent}")

                    if method.upper() == "GET":
                        # 파라미터를 쿼리 스트링으로 추가
                        query_string = "&".join([f"{k}={v}" for k, v in current_params.items()])
                        final_url = f"{url}?{query_string}"
                        await page.goto(final_url, timeout=self.timeout * 1000)
                    elif method.upper() == "POST":
                        # POST 요청
                        final_url = url
                        post_data = current_params

                        # Playwright의 request API를 사용하여 POST 요청
                        captured_response = await self.context.request.post(
                            final_url,
                            data=post_data,
                            timeout=int(self.timeout * 1000)
                        )

                        # 페이지에 임시로 HTML을 로드하여 alert을 감지하기 위해 blank 페이지로 이동
                        await page.goto("about:blank")

                    # 페이지 내용 가져오기
                    content = await page.content()
                    response_text = content  # 전체 내용 저장

                    # 네트워크 응답으로부터 상태 코드 가져오기
                    if captured_response:
                        status_code = captured_response.status
                    else:
                        # 응답이 캡처되지 않았을 경우
                        status_code = 200  # 기본값 설정 (실제로는 정확하지 않을 수 있음)

                    await page.close()

                except asyncio.TimeoutError:
                    end_time = time.time()
                    return {
                        "request_info": {
                            "method": method,
                            "url": final_url
                        },
                        "status_code": -1,
                        "response_text": f"Timeout after {end_time - start_time:.2f}s",
                        "response_time": end_time - start_time,
                        "alert_triggered": False,
                        "alert_message": ""
                    }
                except Exception as error:
                    end_time = time.time()
                    self._logger.error(f"Playwright 요청 중 오류 발생: {error}")
                    return {
                        "request_info": {
                            "method": method,
                            "url": final_url
                        },
                        "status_code": -1,
                        "response_text": f"Error: {type(error).__name__}: {str(error)}",
                        "response_time": end_time - start_time,
                        "alert_triggered": False,
                        "alert_message": ""
                    }

                end_time = time.time()
                return {
                    "request_info": {
                        "method": method,
                        "url": final_url
                    },
                    "status_code": status_code if status_code is not None else 200,
                    "response_text": response_text,
                    "response_time": end_time - start_time,
                    "alert_triggered": alert_triggered,
                    "alert_message": alert_message
                }

            playwright_tasks = [
                asyncio.create_task(playwright_task(url, params, method, item))
                for (url, params, method, item) in playwright_task_args
            ]

            playwright_results = await asyncio.gather(*playwright_tasks, return_exceptions=True)

            for result, item in zip(playwright_results, playwright_task_args):
                if isinstance(result, Exception):
                    self.responses.append({
                        "payload_info": item[3],
                        "response": {
                            "request_info": None,
                            "status_code": -1,
                            "response_text": f"Error: {type(result).__name__}: {str(result)}",
                            "response_time": 0.0,
                            "alert_triggered": False,
                            "alert_message": ""
                        }
                    })
                else:
                    self.responses.append({
                        "payload_info": item[3],
                        "response": result
                    })

        # aiohttp 기반 태스크 처리
        if tasks:
            aiohttp_results = await asyncio.gather(*tasks, return_exceptions=True)
            for result, payload_info in zip(aiohttp_results, payload_tasks_map):
                if isinstance(result, Exception):
                    self.responses.append({
                        "payload_info": payload_info,
                        "response": {
                            "request_info": None,
                            "status_code": -1,
                            "response_text": (
                                f"Error: {type(result).__name__}: {str(result)}"
                            ),
                            "response_time": 0.0,
                            "alert_triggered": False,
                            "alert_message": ""
                        }
                    })
                else:
                    self.responses.append({
                        "payload_info": payload_info,
                        "response": result
                    })

        # Playwright과 브라우저 종료
        await self.close_playwright()

        # 응답 그룹화
        grouped_results = self._group_responses()
        self.final_results = grouped_results  # final_results를 클래스 속성으로 저장
        return grouped_results

    async def _send_single_payload_aiohttp(
        self,
        url: str,
        current_params: Dict[str, str],
        method: str,
        payload_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        기존 aiohttp 방식으로 요청을 전송합니다.

        Args:
            url (str): 요청할 URL.
            current_params (Dict[str, str]): 요청 파라미터.
            method (str): HTTP 메서드 (GET, POST 등).
            payload_info (Dict[str, Any]): 페이로드 관련 정보.

        Returns:
            Dict[str, Any]: 응답 정보가 포함된 딕셔너리.
        """
        request_info = self.prepare_request(url, current_params, method)
        result = await self.submit_request(request_info)
        # XSS 아님
        result["alert_triggered"] = False
        result["alert_message"] = ""
        return result

    def prepare_request(
        self,
        url: str,
        current_params: Dict[str, str],
        method: str
    ) -> Dict[str, Any]:
        """
        요청 정보를 준비합니다.

        Args:
            url (str): 요청할 URL.
            current_params (Dict[str, str]): 요청 파라미터.
            method (str): HTTP 메서드 (GET, POST 등).

        Returns:
            Dict[str, Any]: 요청 정보가 포함된 딕셔너리.
        """
        method_upper = method.upper()

        # 동적으로 헤더 설정
        headers = {
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
            "User-Agent": Util.get_random_user_agent()  # 랜덤 User-Agent 설정
        }
        self._logger.debug(f"Set User-Agent to: {headers['User-Agent']}")

        if method_upper == "GET":
            request_info = {
                "method": method_upper,
                "url": url,
                "params": current_params,
                "data": None,
                "headers": headers
            }
        else:
            request_info = {
                "method": method_upper,
                "url": url,
                "params": None,
                "data": current_params,
                "headers": headers
            }
        return request_info

    async def submit_request(self, request_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        aiohttp로 실제 요청을 전송합니다.

        Args:
            request_info (Dict[str, Any]): 요청 정보가 포함된 딕셔너리.

        Returns:
            Dict[str, Any]: 응답 정보가 포함된 딕셔너리.
        """
        method = request_info["method"].upper()
        url = request_info["url"]
        params = request_info["params"]
        data = request_info["data"]
        headers = request_info["headers"]

        timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
        start_time = time.time()

        try:
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                if method == "GET":
                    async with session.get(url, params=params, headers=headers) as resp:
                        text = await resp.text()
                        status = resp.status
                else:
                    async with session.request(method, url, params=None, json=data, headers=headers) as resp:
                        text = await resp.text()
                        status = resp.status

            end_time = time.time()
            return {
                "request_info": request_info,
                "status_code": status,
                "response_text": text,
                "response_time": end_time - start_time
            }

        except asyncio.TimeoutError:
            end_time = time.time()
            return {
                "request_info": request_info,
                "status_code": -1,
                "response_text": f"Timeout after {end_time - start_time:.2f}s",
                "response_time": end_time - start_time
            }
        except aiohttp.ClientError as error:
            end_time = time.time()
            self._logger.error(f"aiohttp 요청 중 오류 발생: {error}")
            return {
                "request_info": request_info,
                "status_code": -1,
                "response_text": f"ClientError: {type(error).__name__} - {str(error)}",
                "response_time": end_time - start_time
            }

    def _group_responses(self) -> List[Dict[str, Any]]:
        """
        responses를 payload_info 기준으로 그룹화하여 최종 결과를 생성합니다.

        Returns:
            List[Dict[str, Any]]: 그룹화된 최종 결과 리스트.
        """
        grouped: Dict[str, Dict[str, Any]] = {}
        for entry in self.responses:
            payload_info = entry["payload_info"]
            payload_key = json.dumps(payload_info, sort_keys=True)
            if payload_key not in grouped:
                grouped[payload_key] = {
                    "payload_info": payload_info,
                    "responses": []
                }
            grouped[payload_key]["responses"].append(entry["response"])

        final_results: List[Dict[str, Any]] = []
        for _, data in grouped.items():
            payload_info = data["payload_info"]
            responses = data["responses"]

            # 응답 텍스트 길이 차이 계산 (최대 길이 - 최소 길이)
            response_length_difference: Optional[int] = None
            if len(responses) > 1:
                lengths = [len(response["response_text"]) for response in responses]
                length_diff = max(lengths) - min(lengths)
                response_length_difference = length_diff
            else:
                response_length_difference = None  # 없을 경우

            # 각 응답에 payload_info 및 response_length_difference 추가
            for response in responses:
                response_entry = response.copy()
                response_entry["payload_info"] = payload_info
                response_entry["response_length_difference"] = response_length_difference
                final_results.append(response_entry)

        self.final_results = final_results  # final_results를 클래스 속성으로 저장
        return final_results

    def get_final_results(self) -> List[Dict[str, Any]]:
        """
        그룹화된 최종 결과를 반환합니다.

        Returns:
            List[Dict[str, Any]]: 그룹화된 최종 결과 리스트.
        """
        return getattr(self, "final_results", [])

if __name__ == "__main__":

    async def main():
        # 원하는 페이로드 파일 이름을 리스트로 지정
        payload_files = ["common_payload.json", "sqli_payload.json"]  # 필요한 페이로드 파일명 추가
        handler = RequestPayloadHandler(
            payload_files=payload_files,
            timeout=10,
            max_concurrent=5
        )

        if not handler.common_payloads:
            handler._logger.error("페이로드가 로드되지 않았습니다. JSON 파일을 확인하세요.")
            return

        test_url = "http://localhost/index.php"
        params = {"search": ""}  # "search" 파라미터는 페이로드 값으로 설정
        method = "GET"  # "POST"로 변경 가능

        handler._logger.info("\n=== 요청 및 검사 시작 ===")
        scan_results = await handler.send_payloads(
            url=test_url,
            params=params,
            method=method
        )

        # 결과를 저장할 디렉토리 설정
        output_dir = "responses"
        os.makedirs(output_dir, exist_ok=True)

        # 최종 결과를 JSON 형식으로 파일에 저장
        final_output_file = os.path.join(output_dir, "final_results.json")
        try:
            with open(final_output_file, "w", encoding="utf-8") as f:
                json.dump(scan_results, f, indent=4, ensure_ascii=False)
            handler._logger.info(f"최종 결과가 저장되었습니다: {final_output_file}")
        except Exception as error:
            handler._logger.error(f"최종 스캔 결과 파일 저장 실패: {error}")

    asyncio.run(main())