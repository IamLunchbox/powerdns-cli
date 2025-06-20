import pytest
import requests
from click.testing import CliRunner
from powerdns_cli.powerdns_cli import autoprimary_add
import json


class MockUtils:
    def __init__(self, mocker):
        self.mocker = mocker

    def mock_http_get(self, status_code: int, json_output: dict = {}, text_output: str = ''):
        mock_autoprimary_get = self.mocker.MagicMock(spec=requests.Response)
        mock_autoprimary_get.json.return_value = json_output
        mock_autoprimary_get.text.return_value = text_output
        mock_autoprimary_get.status_code = status_code
        mock_autoprimary_get.headers = {'Content-Type': 'application/json'}
        self.mocker.patch('powerdns_cli.utils.http_get', return_value=mock_autoprimary_get)

    def mock_http_post(self, status_code: int, json_output: dict = {}, text_output: str = ''):
        mock_autoprimary_post = self.mocker.MagicMock(spec=requests.Response)
        mock_autoprimary_post.json.return_value = json_output
        mock_autoprimary_post.text.return_value = text_output
        mock_autoprimary_post.status_code = status_code
        mock_autoprimary_post.headers = {'Content-Type': 'application/json'}
        self.mocker.patch('powerdns_cli.utils.http_post', return_value=mock_autoprimary_post)


@pytest.fixture
def mock_utils(mocker):
    return MockUtils(mocker)


def test_autoprimary_add_success(mock_utils):
    mock_utils.mock_http_get(200, [{'ip': '2.2.2.2', 'nameserver': 'ns1.example.com'}])
    mock_utils.mock_http_post(201, text_output='')
    runner = CliRunner()
    result = runner.invoke(
        autoprimary_add,
        ['1.1.1.1', 'ns1.example.com'],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 0
    assert 'added' in json.loads(result.output)['message']


def test_autoprimary_add_already_present(mock_utils):
    mock_utils.mock_http_get(200, [{'ip': '1.1.1.1', 'nameserver': 'ns1.example.com'}])
    mock_utils.mock_http_post(201, text_output='')
    runner = CliRunner()
    result = runner.invoke(
        autoprimary_add,
        ['1.1.1.1', 'ns1.example.com'],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 0
    assert 'present' in json.loads(result.output)['message']


def test_autoprimary_add_permission_denied(mock_utils):
    mock_utils.mock_http_get(200, {})
    mock_utils.mock_http_post(403, {'error': 'Permission denied'})
    runner = CliRunner()
    result = runner.invoke(
        autoprimary_add,
        ['1.1.1.1', 'ns1.example.com'],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 1
    assert 'Permission denied' in json.loads(result.output)['error']
