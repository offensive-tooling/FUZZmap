from typing import Dict, List, Set, Tuple
from dataclasses import dataclass
import asyncio
import aiohttp
from fuzzmap.core.logging.log import Logger
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup


@dataclass
class Param:
    url: str  # URL
    name: str  # name of the parameter
    value: str  # value of the parameter
    param_type: str  # 'url' or 'form'
    method: str  # 'GET' or 'POST'
    path: str  # form action path


class ParamReconHandler:
    def __init__(self, target_urls: str | List[str]):
        # 초기화
        self._target_urls = (
            [target_urls] if isinstance(target_urls, str) else target_urls
        )
        self._parameters: List[Param] = []  # 수집된 파라미터
        self._logger = Logger()

    def _get_urls(self) -> List[str]:
        """처리할 URL 리스트 반환"""
        return self._target_urls

    def _parse_url(self, url: str) -> Dict:
        """URL 구성요소 파싱"""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        return {
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "path": parsed.path,
            "params": query_params,
        }

    def _normalize_url(self, base_url: str, action: str) -> Tuple[str, Dict]:
        """Form action URL 정규화
        base_url path를 제거하고 실제 endpoint path만 추출
        """
        if action.startswith(("http://", "https://")):
            parsed = urlparse(action)
            parsed_base = urlparse(base_url)
            # base_url의 path를 기준으로 제거
            path = (
                parsed.path.replace(parsed_base.path, "", 1)
                if parsed.path.startswith(parsed_base.path)
                else parsed.path
            )
            # 시작 슬래시(/) 유지
            path = path if path.startswith("/") else f"/{path}"
            return path, parse_qs(parsed.query)

        if action.startswith("/"):
            parsed_base = urlparse(base_url)
            # base_url의 path를 기준으로 제거
            path = (
                action.replace(parsed_base.path, "", 1)
                if action.startswith(parsed_base.path)
                else action
            )
            path = path if path.startswith("/") else f"/{path}"
            return path, parse_qs(parsed_base.query)

        parsed_base = urlparse(base_url)
        base_path = parsed_base.path.rsplit("/", 1)[0]
        full_path = f"{base_path}/{action}"
        parsed = urlparse(full_path)
        path = (
            parsed.path.replace(parsed_base.path, "", 1)
            if parsed.path.startswith(parsed_base.path)
            else parsed.path
        )
        path = path if path.startswith("/") else f"/{path}"
        return path, parse_qs(parsed.query)

    async def collect_parameters(self) -> List[Param]:
        """파라미터 수집 시작점"""
        async with aiohttp.ClientSession() as session:
            for url in self._get_urls():
                await self._collect_url_parameters(session, url)
                await self._collect_form_parameters(session, url)

            await self._process_parameters()
            return self._parameters

    async def _collect_url_parameters(
        self, session: aiohttp.ClientSession, url: str
    ) -> None:
        """URL에서 파라미터 수집"""
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    parsed = self._parse_url(url)
                    for param_name, values in parsed["params"].items():
                        for value in values:
                            self._parameters.append(
                                Param(
                                    url=url,
                                    name=param_name,
                                    value=value,
                                    param_type="url",
                                    method="GET",
                                    path=parsed["path"],
                                )
                            )
                    self._logger.info(
                        f"Successfully collected URL parameters from: {url}"
                    )
                else:
                    self._logger.error(
                        f"Failed to fetch URL parameters: {url}, status: {response.status}"
                    )
        except Exception as e:
            self._logger.error(
                f"Error collecting URL parameters: {url}, error: {str(e)}"
            )

    async def _collect_form_parameters(
        self, session: aiohttp.ClientSession, url: str
    ) -> List[str]:
        """Form 요소 파라미터 수집"""
        action_urls = []
        try:
            async with session.get(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                    "Referer": url,
                    "Origin": url,
                },  # for 403 error handling
            ) as response:
                if response.status == 200:
                    text = await response.text()
                    soup = BeautifulSoup(text, "html.parser")
                    forms = soup.find_all("form")

                    for form in forms:
                        method = form.get("method", "GET").upper()
                        action = form.get("action", "")

                        if action:
                            normalized_path, query_params = self._normalize_url(
                                url, action
                            )
                            action_urls.append(normalized_path)

                            # Query parameter 수집
                            for param_name, values in query_params.items():
                                for value in values:
                                    self._parameters.append(
                                        Param(
                                            url=url,
                                            name=param_name,
                                            value=value,
                                            param_type="form-action",
                                            method=method,
                                            path=normalized_path,
                                        )
                                    )
                        # input 요소 수집 (submit 제외)
                        for input_tag in form.find_all("input"):
                            input_type = input_tag.get("type", "text")
                            param_name = input_tag.get("name")
                            if param_name and input_type != "submit":
                                param_value = input_tag.get("value", "")
                                self._parameters.append(
                                    Param(
                                        url=url,
                                        name=param_name,
                                        value=param_value,
                                        param_type=f"form-{input_type}",
                                        method=method,
                                        path=normalized_path if action else "",
                                    )
                                )
                        # select/datalist 요소 수집
                        for select_tag in form.find_all(["select", "datalist"]):
                            param_name = select_tag.get("name")
                            if param_name:
                                options = select_tag.find_all("option")
                                selected_value = next(
                                    (
                                        opt.get("value", opt.text)
                                        for opt in options
                                        if opt.get("selected")
                                    ),
                                    options[0].get("value", "") if options else "",
                                )
                                self._parameters.append(
                                    Param(
                                        url=url,
                                        name=param_name,
                                        value=selected_value,
                                        param_type="form-select",
                                        method=method,
                                        path=normalized_path if action else "",
                                    )
                                )
                        # textarea 요소 수집
                        for textarea in form.find_all("textarea"):
                            param_name = textarea.get("name")
                            if param_name:
                                self._parameters.append(
                                    Param(
                                        url=url,
                                        name=param_name,
                                        value=textarea.text.strip(),
                                        param_type="form-textarea",
                                        method=method,
                                        path=normalized_path if action else "",
                                    )
                                )
                        # button 요소 수집
                        for button in form.find_all("button"):
                            param_name = button.get("name")
                            if param_name:
                                self._parameters.append(
                                    Param(
                                        url=url,
                                        name=param_name,
                                        value=button.get("value", ""),
                                        param_type="form-button",
                                        method=method,
                                        path=normalized_path if action else "",
                                    )
                                )
                    self._logger.info(
                        f"Successfully collected form parameters from: {url}"
                    )
                else:
                    self._logger.error(
                        f"Failed to fetch form parameters: {url}, status: {response.status}"
                    )
        except Exception as e:
            self._logger.error(
                f"Error collecting form parameters: {url}, error: {str(e)}"
            )

        return action_urls

    async def _process_parameters(self) -> None:
        """파라미터 중복 제거 및 정렬"""
        unique_params = {}
        for param in self._parameters:
            param_key = (param.name, param.value, param.method, param.path)
            if param_key not in unique_params or param.param_type.startswith("form"):
                unique_params[param_key] = param

        self._parameters = sorted(list(unique_params.values()), key=lambda x: x.url)


if __name__ == "__main__":

    async def main():
        urls = [
            "http://testphp.vulnweb.com/login.php",
            "http://testhtml5.vulnweb.com/#/popular",
            "http://testasp.vulnweb.com/Search.asp",
            "https://ocw.mit.edu/",
        ]
        # url = "http://testphp.vulnweb.com/"
        # url = "http://testhtml5.vulnweb.com/#/popular"
        # url = "http://testasp.vulnweb.com/Search.asp"
        # paramhandler = ParamReconHandler(url)

        paramhandler = ParamReconHandler(urls)
        params = await paramhandler.collect_parameters()

        print("Collected parameters:")
        for param in params:
            print(
                f"Url: {param.url}, Name: {param.name}, Value: {param.value}, Type: {param.param_type}, Method: {param.method}, Path: {param.path}"
            )

    asyncio.run(main())
