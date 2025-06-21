import pytest
import requests
from click.testing import CliRunner
from powerdns_cli.powerdns_cli import autoprimary_add, autoprimary_list, autoprimary_delete
import json
from unittest.mock import MagicMock as unittest_MagicMock


class MockUtils:
    def __init__(self, mocker):
        self.mocker = mocker

    def mock_http_get(self, status_code: int, json_output: dict = {}, text_output: str = '') -> unittest_MagicMock:
        mock_autoprimary_get = self.mocker.MagicMock(spec=requests.Response)
        mock_autoprimary_get.json.return_value = json_output
        mock_autoprimary_get.text.return_value = text_output
        mock_autoprimary_get.status_code = status_code
        mock_autoprimary_get.headers = {'Content-Type': 'application/json'}
        return self.mocker.patch('powerdns_cli.utils.http_get', return_value=mock_autoprimary_get)

    def mock_http_post(self, status_code: int, json_output: dict = {}, text_output: str = '') -> unittest_MagicMock:
        mock_autoprimary_post = self.mocker.MagicMock(spec=requests.Response)
        mock_autoprimary_post.json.return_value = json_output
        mock_autoprimary_post.text.return_value = text_output
        mock_autoprimary_post.status_code = status_code
        mock_autoprimary_post.headers = {'Content-Type': 'application/json'}
        return self.mocker.patch('powerdns_cli.utils.http_post', return_value=mock_autoprimary_post)

    def mock_http_delete(self, status_code: int, json_output: dict = {}, text_output: str = '') -> unittest_MagicMock:
        mock_autoprimary_delete = self.mocker.MagicMock(spec=requests.Response)
        mock_autoprimary_delete.json.return_value = json_output
        mock_autoprimary_delete.text.return_value = text_output
        mock_autoprimary_delete.status_code = status_code
        mock_autoprimary_delete.headers = {'Content-Type': 'application/json'}
        return self.mocker.patch('powerdns_cli.utils.http_delete', return_value=mock_autoprimary_delete)

@pytest.fixture
def mock_utils(mocker):
    return MockUtils(mocker)


def test_autoprimary_add_success(mock_utils):
    get = mock_utils.mock_http_get(200, [{'ip': '2.2.2.2', 'nameserver': 'ns1.example.com'}])
    post = mock_utils.mock_http_post(201, text_output='')
    runner = CliRunner()
    result = runner.invoke(
        autoprimary_add,
        ['1.1.1.1', 'ns1.example.com'],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 0
    assert 'added' in json.loads(result.output)['message']
    get.assert_called()
    post.assert_called()


def test_autoprimary_add_already_present(mock_utils):
    get = mock_utils.mock_http_get(200, [{'ip': '1.1.1.1', 'nameserver': 'ns1.example.com'}])
    post = mock_utils.mock_http_post(201, text_output='')
    runner = CliRunner()
    result = runner.invoke(
        autoprimary_add,
        ['1.1.1.1', 'ns1.example.com'],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 0
    assert 'present' in json.loads(result.output)['message']
    get.assert_called()
    post.assert_not_called()


def test_autoprimary_list_success(mock_utils):
    get = mock_utils.mock_http_get(200, [{'ip': '2.2.2.2', 'nameserver': 'ns1.example.com'}])
    runner = CliRunner()
    result = runner.invoke(
        autoprimary_list,
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == [{'ip': '2.2.2.2', 'nameserver': 'ns1.example.com'}]
    get.assert_called()


def test_autoprimary_delete_success(mock_utils):
    get = mock_utils.mock_http_get(200, [{'ip': '2.2.2.2', 'nameserver': 'ns1.example.com'}])
    delete = mock_utils.mock_http_delete(204, text_output='')
    runner = CliRunner()
    result = runner.invoke(
        autoprimary_delete,
        ['2.2.2.2', 'ns1.example.com'],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 0
    assert 'deleted' in json.loads(result.output)['message']
    get.assert_called()
    delete.assert_called()

def test_autoprimary_delete_already_absent(mock_utils):
    get = mock_utils.mock_http_get(200, [{'ip': '2.2.2.2', 'nameserver': 'ns1.example.com'}])
    delete = mock_utils.mock_http_delete(201, text_output='')
    runner = CliRunner()
    result = runner.invoke(
        autoprimary_delete,
        ['1.1.1.1', 'ns1.example.com'],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 0
    assert 'already absent' in json.loads(result.output)['message']
    get.assert_called()
    delete.assert_not_called()
