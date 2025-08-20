import json
import copy
import pytest
from click.testing import CliRunner
from powerdns_cli.powerdns_cli import (
    metadata_add, metadata_list, metadata_update, metadata_delete, metadata_extend
)
from powerdns_cli_test_utils import testutils
import requests
from unittest.mock import MagicMock as unittest_MagicMock

@pytest.fixture
def mock_utils(mocker):
    return testutils.MockUtils(mocker)

@pytest.fixture
def conditional_mock_utils(mocker):
    return ConditionalMock(mocker)

example_metadata_list = [{"kind": "SOA-EDIT-API", "metadata": ["DEFAULT"], "type": "Metadata"}, {"kind": "ALSO-NOTIFY", "metadata": ["192.0.2.1:5305", "192.0.2.2:5305"], "type": "Metadata"}]
@pytest.fixture
def example_metadata():
    return copy.deepcopy(example_metadata_list)

example_soa_edit_api_dict = {"kind": "SOA-EDIT-API", "metadata": ["DEFAULT"], "type": "Metadata"}
@pytest.fixture
def example_soa_edit_api():
    return copy.deepcopy(example_soa_edit_api_dict)

example_also_notify_dict = {"kind": "ALSO-NOTIFY", "metadata": ["192.0.2.1:5305", "192.0.2.2:5305"], "type": "Metadata"}
@pytest.fixture
def example_also_notify():
    return copy.deepcopy(example_also_notify_dict)

example_new_data_dict = {"kind": "NEW-DATA", "metadata": ["test123"], "type": "Metadata"}
@pytest.fixture
def example_new_data():
    return copy.deepcopy(example_new_data_dict)

class ConditionalMock(testutils.MockUtils):
    def mock_http_get(self) -> unittest_MagicMock:
        def side_effect(*args, **kwargs):
            match args[0]:
                case "http://example.com/api/v1/servers/localhost/zones/example.com./metadata":
                    json_output = example_metadata_list
                    status_code = 200
                case "http://example.com/api/v1/servers/localhost/zones/example.com./metadata/ALSO-NOTIFY":
                    json_output = example_also_notify_dict
                    status_code = 200
                case "http://example.com/api/v1/servers/localhost/zones/example.com./metadata/SOA-EDIT-API":
                    json_output = example_soa_edit_api_dict
                    status_code = 200
                case "http://example.com/api/v1/servers/localhost/zones/example.com./metadata/NEW-DATA":
                    json_output = {"error": "Not found"}
                    status_code = 404
                case _:
                    raise NotImplementedError(f"An unexpected url-path was called: {args[0]}")
            mock_http_get = self.mocker.MagicMock(spec=requests.Response)
            mock_http_get.status_code = status_code
            mock_http_get.json.return_value = json_output
            mock_http_get.headers = {'Content-Type': 'application/json'}
            return mock_http_get
        return self.mocker.patch('powerdns_cli.utils.http_get', side_effect=side_effect)

def test_metadata_add_success(mock_utils, conditional_mock_utils, example_new_data):
    get = conditional_mock_utils.mock_http_get()
    post = mock_utils.mock_http_post(201, json_output=example_new_data)
    runner = CliRunner()
    result = runner.invoke(
        metadata_add,
        ['example.com', example_new_data["kind"], example_new_data["metadata"][0]],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == example_new_data
    post.assert_called()
    get.assert_called()


def test_metadata_add_idempotence(mock_utils, conditional_mock_utils, example_soa_edit_api):
    get = conditional_mock_utils.mock_http_get()
    post = mock_utils.mock_http_post(201, json_output=example_soa_edit_api)
    runner = CliRunner()
    result = runner.invoke(
        metadata_add,
        ['example.com', 'SOA-EDIT-API', example_soa_edit_api["metadata"][0]],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 0
    assert "already present" in json.loads(result.output)["message"]
    get.assert_called()
    post.assert_not_called()

def test_metadata_add_failed(mock_utils, conditional_mock_utils, example_new_data):
    get = conditional_mock_utils.mock_http_get()
    post = mock_utils.mock_http_post(500, json_output={"error": "Request failed"})
    runner = CliRunner()
    result = runner.invoke(
        metadata_add,
        ['example.com', example_new_data["kind"], example_new_data["metadata"][0]],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 1
    assert json.loads(result.output) == {"error": "Request failed"}
    post.assert_called()
    get.assert_called()

def test_metadata_list_success(conditional_mock_utils, example_metadata):
    get = conditional_mock_utils.mock_http_get()
    runner = CliRunner()
    result = runner.invoke(
        metadata_list,
        ['example.com'],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == example_metadata
    get.assert_called()


def test_metadata_extend_success(mock_utils, conditional_mock_utils, example_also_notify):
    get = conditional_mock_utils.mock_http_get()
    example_also_notify["metadata"].extend("192.168.123.111")
    post = mock_utils.mock_http_post(201, json_output=example_also_notify)
    runner = CliRunner()
    result = runner.invoke(
        metadata_extend,
        ['example.com', example_also_notify["kind"], "192.168.123.111"],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == example_also_notify
    post.assert_called()
    get.assert_called()


def test_metadata_extend_idempotence(mock_utils, conditional_mock_utils, example_also_notify):
    get = conditional_mock_utils.mock_http_get()
    post = mock_utils.mock_http_post(201, json_output=example_also_notify)
    runner = CliRunner()
    result = runner.invoke(
        metadata_extend,
        ['example.com', example_also_notify["kind"], example_also_notify["metadata"][1]],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 0
    assert "already present" in json.loads(result.output)["message"]
    post.assert_not_called()
    get.assert_called()

def test_metadata_extend_failed(mock_utils, conditional_mock_utils, example_also_notify):
    get = conditional_mock_utils.mock_http_get()
    post = mock_utils.mock_http_post(500, json_output={"error": "Request failed"})
    runner = CliRunner()
    result = runner.invoke(
        metadata_extend,
        ['example.com', example_also_notify["kind"], "192.168.123.111"],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 1
    assert json.loads(result.output) == {"error": "Request failed"}
    post.assert_called()
    get.assert_called()
