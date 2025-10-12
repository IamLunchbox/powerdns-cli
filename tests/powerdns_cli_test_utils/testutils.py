import copy
from io import IOBase
from unittest.mock import MagicMock

import pytest
import requests

from powerdns_cli.utils.validation import ContextObj


@pytest.fixture
def mock_utils(mocker):
    return MockUtils(mocker)


testenvironment = {
    "POWERDNS_CLI_URL": "http://example.com",
    "POWERDNS_CLI_APIKEY": "testkey",
    "POWERDNS_CLI_API_VERSION": "5",
}


@pytest.fixture
def testobject():
    obj = ContextObj()
    obj.config["apihost"] = "http://example.com"
    obj.config["api_version"] = 5
    obj.config["debug"] = False
    obj.config["json"] = True
    obj.config["pytest"] = True
    return obj


class MockUtils:
    def __init__(self, mocker: MagicMock):
        self.mocker = mocker
        self.mocker.patch(
            "powerdns_cli.utils.main.http_get",
            side_effect=RuntimeError("http_get was unexpectedly called!"),
        )
        self.mocker.patch(
            "powerdns_cli.utils.main.http_post",
            side_effect=RuntimeError("http_post was unexpectedly called!"),
        )
        self.mocker.patch(
            "powerdns_cli.utils.main.http_put",
            side_effect=RuntimeError("http_put was unexpectedly called!"),
        )
        self.mocker.patch(
            "powerdns_cli.utils.main.http_delete",
            side_effect=RuntimeError("http_delete was unexpectedly called!"),
        )
        self.mocker.patch(
            "powerdns_cli.utils.main.http_patch",
            side_effect=RuntimeError("http_patch was unexpectedly called!"),
        )

    def mock_http_get(
        self, status_code: int, json_output: dict | list = None, text_output: str = ""
    ) -> MagicMock:
        mock_http_get = self.mocker.MagicMock(spec=requests.Response)
        mock_http_get.json.return_value = json_output
        mock_http_get.text.return_value = text_output
        mock_http_get.status_code = status_code
        mock_http_get.reason = "OK"
        mock_http_get.headers = {"Content-Type": "application/json"}
        return self.mocker.patch("powerdns_cli.utils.main.http_get", return_value=mock_http_get)

    def mock_http_post(
        self, status_code: int, json_output: dict | list = None, text_output: str = ""
    ) -> MagicMock:
        mock_http_post = self.mocker.MagicMock(spec=requests.Response)
        mock_http_post.json.return_value = json_output
        mock_http_post.text.return_value = text_output
        mock_http_post.status_code = status_code
        mock_http_post.reason = "OK"
        mock_http_post.headers = {"Content-Type": "application/json"}
        return self.mocker.patch("powerdns_cli.utils.main.http_post", return_value=mock_http_post)

    def mock_http_delete(
        self, status_code: int, json_output: dict | list = None, text_output: str = ""
    ) -> MagicMock:
        mock_http_delete = self.mocker.MagicMock(spec=requests.Response)
        mock_http_delete.json.return_value = json_output
        mock_http_delete.text.return_value = text_output
        mock_http_delete.status_code = status_code
        mock_http_delete.reason = "OK"
        mock_http_delete.headers = {"Content-Type": "application/json"}
        return self.mocker.patch(
            "powerdns_cli.utils.main.http_delete", return_value=mock_http_delete
        )

    def mock_http_put(
        self, status_code: int, json_output: dict | list = None, text_output: str = ""
    ) -> MagicMock:
        mock_http_put = self.mocker.MagicMock(spec=requests.Response)
        mock_http_put.json.return_value = json_output
        mock_http_put.text.return_value = text_output
        mock_http_put.status_code = status_code
        mock_http_put.reason = "OK"
        mock_http_put.headers = {"Content-Type": "application/json"}
        return self.mocker.patch("powerdns_cli.utils.main.http_put", return_value=mock_http_put)

    def mock_http_patch(
        self, status_code: int, json_output: dict | list = None, text_output: str = ""
    ) -> MagicMock:
        mock_http_patch = self.mocker.MagicMock(spec=requests.Response)
        mock_http_patch.json.return_value = json_output
        mock_http_patch.text.return_value = text_output
        mock_http_patch.status_code = status_code
        mock_http_patch.reason = "OK"
        mock_http_patch.headers = {"Content-Type": "application/json"}
        return self.mocker.patch("powerdns_cli.utils.main.http_patch", return_value=mock_http_patch)


class MockFile:
    def __init__(self, mocker: MagicMock):
        self.mocker = mocker
        self.mocker.patch("builtins.open", MagicMock(spec=IOBase))

    def mock_settings_import(self, file_contents: dict | list):
        return self.mocker.patch(
            "powerdns_cli.utils.main.extract_file", return_value=copy.deepcopy(file_contents)
        )
