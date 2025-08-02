import requests
from unittest.mock import MagicMock as unittest_MagicMock


class MockUtils:
    def __init__(self, mocker):
        self.mocker = mocker

    def mock_http_get(self, status_code: int, json_output: dict | list = None, text_output: str = '') -> unittest_MagicMock:
        mock_http_get = self.mocker.MagicMock(spec=requests.Response)
        mock_http_get.json.return_value = json_output
        mock_http_get.text.return_value = text_output
        mock_http_get.status_code = status_code
        mock_http_get.headers = {'Content-Type': 'application/json'}
        return self.mocker.patch('powerdns_cli.utils.http_get', return_value=mock_http_get)

    def mock_http_post(self, status_code: int, json_output: dict | list = None, text_output: str = '') -> unittest_MagicMock:
        mock_http_post = self.mocker.MagicMock(spec=requests.Response)
        mock_http_post.json.return_value = json_output
        mock_http_post.text.return_value = text_output
        mock_http_post.status_code = status_code
        mock_http_post.headers = {'Content-Type': 'application/json'}
        return self.mocker.patch('powerdns_cli.utils.http_post', return_value=mock_http_post)

    def mock_http_delete(self, status_code: int, json_output: dict | list = None, text_output: str = '') -> unittest_MagicMock:
        mock_http_delete = self.mocker.MagicMock(spec=requests.Response)
        mock_http_delete.json.return_value = json_output
        mock_http_delete.text.return_value = text_output
        mock_http_delete.status_code = status_code
        mock_http_delete.headers = {'Content-Type': 'application/json'}
        return self.mocker.patch('powerdns_cli.utils.http_delete', return_value=mock_http_delete)

    def mock_http_put(self, status_code: int, json_output: dict | list = None, text_output: str = '') -> unittest_MagicMock:
        mock_http_put = self.mocker.MagicMock(spec=requests.Response)
        mock_http_put.json.return_value = json_output
        mock_http_put.text.return_value = text_output
        mock_http_put.status_code = status_code
        mock_http_put.headers = {'Content-Type': 'application/json'}
        return self.mocker.patch('powerdns_cli.utils.http_put', return_value=mock_http_put)

    def mock_http_patch(self, status_code: int, json_output: dict | list = None, text_output: str = '') -> unittest_MagicMock:
        mock_http_patch = self.mocker.MagicMock(spec=requests.Response)
        mock_http_patch.json.return_value = json_output
        mock_http_patch.text.return_value = text_output
        mock_http_patch.status_code = status_code
        mock_http_patch.headers = {'Content-Type': 'application/json'}
        return self.mocker.patch('powerdns_cli.utils.http_patch', return_value=mock_http_patch)
