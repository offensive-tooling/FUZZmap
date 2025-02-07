import asyncio
import aiohttp
import time
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, asdict
import json  # <-- JSON 출력을 위해 추가

from playwright.async_api import async_playwright, Dialog, Response

from fuzzmap.core.logging.log import Logger
from fuzzmap.core.util.util import Util


@dataclass
class ServerSideResponse:
    payload: str
    status_code: int
    response_text: str
    response_time: float
    response_length: int


@dataclass
class ClientSideResponse:
    payload: str
    status_code: int
    response_text: str
    response_time: float
    response_length: int
    alert_triggered: bool = False
    alert_message: str = ""


class RequestPayloadHandler:
    """
    - 서버사이드: aiohttp를 사용하여 HTTP 요청 전송
    - 클라이언트사이드: Playwright를 사용하여 XSS 검사 및 HTTP 요청 전송
    - 'payload'가 리스트이든 단일 값이든 일관되게 처리
    - 에러(Timeout, ClientError) 시 status=500, response_text에 에러 표시
    """
    _playwright: Optional[Any] = None
    _browser: Optional[Any] = None
    _context: Optional[Any] = None
    _lock: asyncio.Lock = asyncio.Lock()
    _logger: Logger = Logger()

    @classmethod
    async def _initialize_playwright(cls) -> None:
        async with cls._lock:
            if cls._playwright is None:
                cls._playwright = await async_playwright().start()
                cls._browser = await cls._playwright.chromium.launch(headless=True)
                cls._context = await cls._browser.new_context()
                # 불필요한 리소스 차단 (이미지, CSS, 폰트 등)
                await cls._context.route(
                    "**/*.{png,jpg,jpeg,gif,svg,css,woff,woff2}",
                    lambda route: asyncio.create_task(route.abort())
                )
                cls._logger.info("Playwright 초기화 및 불필요한 리소스 차단 설정 완료.")

    @classmethod
    async def _close_playwright_async(cls) -> None:
        try:
            if cls._context:
                await cls._context.close()
                cls._logger.info("브라우저 컨텍스트 종료.")
            if cls._browser:
                await cls._browser.close()
                cls._logger.info("브라우저 종료.")
            if cls._playwright:
                await cls._playwright.stop()
                cls._logger.info("Playwright 인스턴스 종료.")
        except Exception as error:
            cls._logger.error(f"Playwright 종료 중 오류 발생: {error}")
        finally:
            cls._playwright = None
            cls._browser = None
            cls._context = None

    @classmethod
    async def send_serverside(
        cls,
        url: str,
        params: Dict[str, str],
        method: str = "GET",
        payloads: Optional[List[str]] = None,
        timeout: float = 10.0,
        max_concurrent: int = 10
    ) -> List[ServerSideResponse]:
        if not payloads:
            cls._logger.error("전송할 페이로드가 없습니다.")
            return []

        semaphore = asyncio.Semaphore(max_concurrent)

        async def _process_serverside_request(
            session: aiohttp.ClientSession, payload: str
        ) -> ServerSideResponse:
            async with semaphore:
                current_params = cls.insert_payload(params, payload)
                headers = cls.get_headers()
                cls._logger.debug(f"Set User-Agent to: {headers['User-Agent']}")
                start_time = time.time()
                try:
                    if method.upper() == "GET":
                        async with session.get(
                            url, params=current_params, headers=headers
                        ) as resp:
                            text = await resp.text()
                            status = resp.status
                    else:
                        async with session.request(
                            method.upper(), url, data=current_params, headers=headers
                        ) as resp:
                            text = await resp.text()
                            status = resp.status
                    end_time = time.time()
                    response_time = end_time - start_time
                    response_length = len(text)
                    return ServerSideResponse(
                        payload=payload,
                        status_code=status,
                        response_text=text,
                        response_time=response_time,
                        response_length=response_length,
                    )
                except asyncio.TimeoutError:
                    end_time = time.time()
                    response_time = end_time - start_time
                    cls._logger.error(
                        f"aiohttp 요청 Timeout: {url} with payload: {payload}"
                    )
                    return ServerSideResponse(
                        payload=payload,
                        status_code=504,
                        response_text=f"Timeout after {response_time:.2f}s",
                        response_time=response_time,
                        response_length=0,
                    )
                except aiohttp.ClientError as error:
                    end_time = time.time()
                    response_time = end_time - start_time
                    cls._logger.error(
                        f"aiohttp 요청 중 오류 발생: {error} with payload: {payload}"
                    )
                    return ServerSideResponse(
                        payload=payload,
                        status_code=500,
                        response_text=f"ClientError: {type(error).__name__} - {str(error)}",
                        response_time=response_time,
                        response_length=0,
                    )

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=timeout)
        ) as session:
            tasks = [
                asyncio.create_task(_process_serverside_request(session, payload))
                for payload in payloads
            ]
            cls._logger.info("서버사이드 페이로드 전송 시작.")
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            cls._logger.info("서버사이드 페이로드 전송 완료.")

        server_responses: List[ServerSideResponse] = []
        for response in responses:
            if isinstance(response, Exception):
                cls._logger.error(f"서버사이드 요청 중 오류 발생: {response}")
                server_responses.append(
                    ServerSideResponse(
                        payload="",
                        status_code=500,
                        response_text=f"Error: {type(response).__name__}: {str(response)}",
                        response_time=0.0,
                        response_length=0,
                    )
                )
            else:
                server_responses.append(response)

        return server_responses

    @classmethod
    async def send_clientside(
        cls,
        url: str,
        params: Dict[str, str],
        method: str = "GET",
        payloads: Optional[List[str]] = None,
        timeout: float = 10.0,
        max_concurrent: int = 10
    ) -> List[ClientSideResponse]:
        if not payloads:
            cls._logger.error("전송할 페이로드가 없습니다.")
            return []

        semaphore = asyncio.Semaphore(max_concurrent)

        async def _process_clientside_request(
            context: Any, payload: str
        ) -> ClientSideResponse:
            async with semaphore:
                current_params = cls.insert_payload(params, payload)
                method_upper = method.upper()
                headers = cls.get_headers()
                cls._logger.debug(f"Set User-Agent to: {headers['User-Agent']}")
                start_time = time.time()
                alert_triggered = False
                alert_message = ""
                status_code: Optional[int] = None
                response_text = ""
                response_length = 0
                final_url = ""

                try:
                    page = await context.new_page()

                    # 네트워크 응답 핸들러
                    captured_response: Optional[Response] = None

                    async def handle_response(response: Response) -> None:
                        nonlocal captured_response

                        if response.url == final_url:
                            captured_response = response

                    page.on("response", handle_response)

                    # dialog 이벤트 핸들러
                    async def handle_dialog(dialog: Dialog) -> None:
                        nonlocal alert_triggered, alert_message
                        if dialog.type == "alert":
                            alert_triggered = True
                            alert_message = dialog.message
                        await dialog.dismiss()

                    page.on("dialog", handle_dialog)

                    # 랜덤 User-Agent 설정
                    await page.set_extra_http_headers(headers)

                    if method_upper == "GET":
                        # 파라미터를 쿼리 스트링으로 추가
                        query_string = "&".join(
                            [f"{k}={v}" for k, v in current_params.items()]
                        )
                        final_url = f"{url}?{query_string}"
                        await page.goto(final_url, timeout=int(timeout * 1000))

                        # 페이지 내용 가져오기
                        content = await page.content()
                        response_text = content
                        response_length = len(content)

                        # 네트워크 응답 상태 코드 가져오기
                        if captured_response:
                            status_code = captured_response.status
                        else:
                            status_code = 200  # fallback

                    elif method_upper == "POST":
                        # POST 요청
                        final_url = url
                        post_data = current_params

                        # Playwright의 request API를 사용하여 POST 요청 먼저 실행
                        captured_response = await context.request.post(
                            final_url, form=post_data, timeout=int(timeout * 1000)
                        )
                        captured_content = await captured_response.text()
                        await page.set_content(captured_content)

                        content = await page.content()
                        response_text = content
                        response_length = len(content)
                        
                        status_code = captured_response.status

                    await page.close()

                except asyncio.TimeoutError:
                    end_time = time.time()
                    response_time = end_time - start_time
                    cls._logger.error(
                        f"Playwright 요청 Timeout: {final_url} with payload: {payload}"
                    )
                    return ClientSideResponse(
                        payload=payload,
                        status_code=504,
                        response_text=f"Timeout after {response_time:.2f}s",
                        response_time=response_time,
                        response_length=0,
                        alert_triggered=False,
                        alert_message="",
                    )
                except Exception as error:
                    end_time = time.time()
                    response_time = end_time - start_time
                    cls._logger.error(
                        f"Playwright 요청 중 오류 발생: {error} with payload: {payload}"
                    )
                    return ClientSideResponse(
                        payload=payload,
                        status_code=500,
                        response_text=f"Error: {type(error).__name__}: {str(error)}",
                        response_time=response_time,
                        response_length=0,
                        alert_triggered=False,
                        alert_message="",
                    )

                end_time = time.time()
                response_time = end_time - start_time

                return ClientSideResponse(
                    payload=payload,
                    status_code=status_code if status_code is not None else 200,
                    response_text=response_text,
                    response_time=response_time,
                    response_length=response_length,
                    alert_triggered=alert_triggered,
                    alert_message=alert_message,
                )

        async def _initialize_playwright_if_needed() -> None:
            if cls._playwright is None:
                await cls._initialize_playwright()

        # Playwright 초기화 (싱글톤)
        await _initialize_playwright_if_needed()

        try:
            tasks = [
                asyncio.create_task(_process_clientside_request(cls._context, payload))
                for payload in payloads
            ]
            cls._logger.info("클라이언트사이드 페이로드 전송 시작.")
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            cls._logger.info("클라이언트사이드 페이로드 전송 완료.")

            client_responses: List[ClientSideResponse] = []
            for response in responses:
                if isinstance(response, Exception):
                    cls._logger.error(f"클라이언트사이드 요청 중 오류 발생: {response}")
                    client_responses.append(
                        ClientSideResponse(
                            payload="",
                            status_code=500,
                            response_text=f"Error: {type(response).__name__}: {str(response)}",
                            response_time=0.0,
                            response_length=0,
                            alert_triggered=False,
                            alert_message="",
                        )
                    )
                else:
                    client_responses.append(response)

            return client_responses

        finally:
            # Playwright 리소스 정리
            await cls._close_playwright_async()

    @classmethod
    def insert_payload(cls, params: Dict[str, str], payload: str) -> Dict[str, str]:
        current_params = params.copy()  

        # 값이 빈 모든 키에 페이로드 삽입
        empty_keys = [k for k, v in current_params.items() if not v]
        if empty_keys:
            for key in empty_keys:
                cls._logger.debug(f"Payload를 '{key}' 파라미터에 삽입합니다.")
                current_params[key] = payload
        else:
            # 모든 파라미터에 값이 있는 경우, 기본 키에 페이로드 삽입
            if current_params:
                default_key = next(iter(current_params.keys()), "payload")
                cls._logger.debug(
                    f"모든 파라미터에 값이 있습니다. '{default_key}' 파라미터에 페이로드를 삽입합니다."
                )
                current_params[default_key] = payload
            else:
                # params가 비어있는 경우 기본 키 사용
                cls._logger.debug(
                    "params가 비어있습니다. 'payload' 키에 페이로드를 삽입합니다."
                )
                current_params["payload"] = payload

        return current_params

    @classmethod
    def get_headers(cls) -> Dict[str, str]:
        headers = {
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
            "User-Agent": Util.get_random_user_agent(),  # 랜덤 User-Agent 설정
        }
        cls._logger.debug(f"Set User-Agent to: {headers['User-Agent']}")
        return headers


if __name__ == "__main__":
    import sys

    async def test_payload():
        """
        특정 사이트에 하나 또는 여러 개의 페이로드를 테스트합니다.
        """
        # 테스트할 URL과 파라미터 설정
        test_url = "http://localhost/login.php"
        params = {"name": "", "password":""}
        method = "post"  # 요청 메서드 (GET 또는 POST)
        payloads1 = ["' OR '1'='1' --", "\"' AND IF(1=1,SLEEP(5),0)--"]
        payloads2 = [
            "'\"<script>alert({{7*7}})</script><!---",
            "<img src=x onerror='javascript:alert(6)'>"
        ]

        try:
            # 서버사이드 테스트
            print("\n=== 서버사이드 테스트 시작 ===")
            server_results = await RequestPayloadHandler.send_serverside(
                url=test_url,
                params=params,
                method=method,
                payloads=payloads1,
            )
            for result in server_results:
                print(f"\nPayload: {result.payload}")
                print(f"Status Code: {result.status_code}")
                print(f"Response Time: {result.response_time:.2f}s")
                print(f"Response Length: {result.response_length}")
                print(f"Response Text: {result.response_text[:1000]}...")  # 응답 텍스트 일부 출력

            # 클라이언트사이드 테스트
            print("\n=== 클라이언트사이드 테스트 시작 ===")
            client_results = await RequestPayloadHandler.send_clientside(
                url=test_url,
                params=params,
                method=method,
                payloads=payloads2,
            )
            for result in client_results:
                print(f"\nPayload: {result.payload}")
                print(f"Status Code: {result.status_code}")
                print(f"Response Time: {result.response_time:.2f}s")
                print(f"Response Length: {result.response_length}")
                print(f"Alert Triggered: {result.alert_triggered}")
                print(f"Alert Message: {result.alert_message}")
                print(f"Response Text: {result.response_text[:1000]}...")  # 응답 텍스트 일부 출력

        except Exception as error:
            print(f"테스트 중 오류 발생: {error}", file=sys.stderr)

    # asyncio 실행
    asyncio.run(test_payload())
