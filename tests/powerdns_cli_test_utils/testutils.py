import requests
from unittest.mock import MagicMock as unittest_MagicMock


class MockUtils:
    def __init__(self, mocker):
        self.mocker = mocker

    def mock_http_get(self, status_code: int, json_output: dict | list = None, text_output: str = '') -> unittest_MagicMock:
        mock_autoprimary_get = self.mocker.MagicMock(spec=requests.Response)
        mock_autoprimary_get.json.return_value = json_output
        mock_autoprimary_get.text.return_value = text_output
        mock_autoprimary_get.status_code = status_code
        mock_autoprimary_get.headers = {'Content-Type': 'application/json'}
        return self.mocker.patch('powerdns_cli.utils.http_get', return_value=mock_autoprimary_get)

    def mock_http_post(self, status_code: int, json_output: dict | list = None, text_output: str = '') -> unittest_MagicMock:
        mock_autoprimary_post = self.mocker.MagicMock(spec=requests.Response)
        mock_autoprimary_post.json.return_value = json_output
        mock_autoprimary_post.text.return_value = text_output
        mock_autoprimary_post.status_code = status_code
        mock_autoprimary_post.headers = {'Content-Type': 'application/json'}
        return self.mocker.patch('powerdns_cli.utils.http_post', return_value=mock_autoprimary_post)

    def mock_http_delete(self, status_code: int, json_output: dict | list = None, text_output: str = '') -> unittest_MagicMock:
        mock_autoprimary_delete = self.mocker.MagicMock(spec=requests.Response)
        mock_autoprimary_delete.json.return_value = json_output
        mock_autoprimary_delete.text.return_value = text_output
        mock_autoprimary_delete.status_code = status_code
        mock_autoprimary_delete.headers = {'Content-Type': 'application/json'}
        return self.mocker.patch('powerdns_cli.utils.http_delete', return_value=mock_autoprimary_delete)

    def mock_http_put(self, status_code: int, json_output: dict | list = None, text_output: str = '') -> unittest_MagicMock:
        mock_autoprimary_put = self.mocker.MagicMock(spec=requests.Response)
        mock_autoprimary_put.json.return_value = json_output
        mock_autoprimary_put.text.return_value = text_output
        mock_autoprimary_put.status_code = status_code
        mock_autoprimary_put.headers = {'Content-Type': 'application/json'}
        return self.mocker.patch('powerdns_cli.utils.http_post', return_value=mock_autoprimary_put)
