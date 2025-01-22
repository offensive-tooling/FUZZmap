from typing import Dict, List
from dataclasses import dataclass
import asyncio
import aiohttp
from fuzzmap.core.logging.log import Logger
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup


@dataclass
class Param:
    name: str
    value: str
    param_type: str  # 'url' or 'form'
    method: str  # 'GET' or 'POST'


class ParamReconHandler:
    def __init__(self, target_urls: str | List[str]):
        self._target_urls = (
            [target_urls] if isinstance(target_urls, str) else target_urls
        )
        self._parameters: List[Param] = []
        self._logger = Logger()

    def _get_urls(self) -> List[str]:
        """Return the current list of URLs to process"""
        return self._target_urls

    def _parse_url(self, url: str) -> Dict:
        """return components parsed from the URL"""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        return {
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "path": parsed.path,
            "params": query_params,
        }

    async def collect_parameters(self) -> List[Param]:
        async with aiohttp.ClientSession() as session:
            tasks = []
            for url in self._get_urls():
                tasks.append(self._collect_url_parameters(session, url))
                tasks.append(self._collect_form_parameters(session, url))

            await asyncio.gather(*tasks)

        await self._process_parameters()  # 여기서 _process_parameters를 호출
        return self._parameters

    async def _collect_url_parameters(
        self, session: aiohttp.ClientSession, url: str
    ) -> None:
        """collect URL parameters from the URL"""
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    parsed = self._parse_url(url)
                    for param_name, values in parsed["params"].items():
                        for value in values:
                            self._parameters.append(
                                Param(
                                    name=param_name,
                                    value=value,
                                    param_type="url",
                                    method="GET",
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
    ) -> None:
        """collect form parameters from the form"""
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    soup = BeautifulSoup(text, "html.parser")

                    # search for forms
                    forms = soup.find_all("form")
                    for form in forms:
                        method = form.get("method", "GET").upper()

                        # 1. normal input fields
                        for input_tag in form.find_all("input"):
                            # submit은 제외하고 나머지는 모두 처리 -> 추후 추가
                            input_type = input_tag.get("type", "text")
                            # hidden, text, password, email, number, tel, search, url,
                            # date, time, datetime-local, month, week, color,
                            # radio, checkbox 등 모든 input 타입 처리
                            param_name = input_tag.get("name")
                            if param_name:
                                param_value = input_tag.get("value", "")
                                self._parameters.append(
                                    Param(
                                        name=param_name,
                                        value=param_value,
                                        param_type=f"form-{input_type}",
                                        method=method,
                                    )
                                )

                        # 2. Select and Datalist
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
                                        name=param_name,
                                        value=selected_value,
                                        param_type="form-select",
                                        method=method,
                                    )
                                )

                        # 3. Textarea
                        for textarea in form.find_all("textarea"):
                            param_name = textarea.get("name")
                            if param_name:
                                self._parameters.append(
                                    Param(
                                        name=param_name,
                                        value=textarea.text.strip(),
                                        param_type="form-textarea",
                                        method=method,
                                    )
                                )

                        # 4. Button
                        for button in form.find_all("button"):
                            param_name = button.get("name")
                            if param_name:
                                self._parameters.append(
                                    Param(
                                        name=param_name,
                                        value=button.get("value", ""),
                                        param_type="form-button",
                                        method=method,
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

    async def _process_parameters(self) -> None:
        unique_params = {}

        for param in self._parameters:
            param_key = (param.name, param.value, param.method)
            if param_key not in unique_params or param.param_type.startswith("form"):
                unique_params[param_key] = param

        filtered_params = list(unique_params.values())

        # sort by name
        self._parameters = sorted(filtered_params, key=lambda x: x.name)


if __name__ == "__main__":

    async def main():
        # single url for test
        url = "http://testphp.vulnweb.com/login.php"
        paramhandler = ParamReconHandler(url)
        params = await paramhandler.collect_parameters()
        print("Single URL parameters:")
        for param in params:
            print(
                f"Name: {param.name}, Value: {param.value}, Type: {param.param_type}, Method: {param.method}"
            )

        # multiple urls for test
        url_lst = [
            "http://localhost/index.php?type=title",
        ]
        paramhandler = ParamReconHandler(url_lst)
        params = await paramhandler.collect_parameters()
        print("\nMultiple URL parameters:")
        for param in params:
            print(
                f"Name: {param.name}, Value: {param.value}, Type: {param.param_type}, Method: {param.method}"
            )

    asyncio.run(main())
