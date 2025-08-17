import json
import copy
import pytest
from click.testing import CliRunner
from powerdns_cli.powerdns_cli import (
    tsigkey_add, tsigkey_delete, tsigkey_export, tsigkey_list, tsigkey_update
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

example_new_tsigkey_dict = {"algorithm": "hmac-sha256", "id": "test.", "key": "AvyIiTEIaHxfwHsif+0Z39cxTra8P8KcyPpMNQdANzHgm73rvXPFqZbgmPolE6jWEKYrM5KruSJyuoAoCpY8Nw==", "name": "test", "type": "TSIGKey"}
@pytest.fixture
def example_new_tsigkey():
    return copy.deepcopy(example_new_tsigkey_dict)

example_tsigkey_test_1_dict = {"algorithm": "hmac-sha512", "id": "test1.", "key": "WRoq4mEXTRAYMchV6/YfOWwHR5hdJ9zgWlIm0bVgrX9BoYIsLjy6jErVThBUrCffguQo2W+sHri7h9h8CaHlag==", "name": "test1", "type": "TSIGKey"}
@pytest.fixture
def example_tsigkey_test1():
    return copy.deepcopy(example_tsigkey_test_1_dict)

example_tsigkey_test_2_dict = {"algorithm": "hmac-sha384", "id": "test2.", "key": "yZYHOEtBoYuRaN0Qwn9Z21EQ7FwQLzmbal7PLTJKNwL0Ql3Yiaxnk8+RV6lZNvxiBeZQqHlw1uEUj1l7IX7mhA==", "name": "test2", "type": "TSIGKey"}
@pytest.fixture
def example_tsigkey_test2():
    return copy.deepcopy(example_tsigkey_test_2_dict)

example_tsigkey_list_list = [{"algorithm": "hmac-sha512", "id": "test1.", "key": "", "name": "test1", "type": "TSIGKey"}, {"algorithm": "hmac-sha384", "id": "test2.", "key": "", "name": "test2", "type": "TSIGKey"}]
@pytest.fixture
def example_tsigkey_list():
    return copy.deepcopy(example_tsigkey_list_list)

class ConditionalMock(testutils.MockUtils):
    def mock_http_get(self) -> unittest_MagicMock:
        def side_effect(*args, **kwargs):
            match args[0]:
                case "http://example.com/api/v1/servers/localhost/tsigkeys":
                    json_output = example_tsigkey_list_list
                    status_code = 200
                case "http://example.com/api/v1/servers/localhost/tsigkeys/test1":
                    json_output = example_tsigkey_test_1_dict
                    status_code = 200
                case "http://example.com/api/v1/servers/localhost/tsigkeys/test2":
                    json_output = example_tsigkey_test_2_dict
                    status_code = 200
                case value if "http://example.com/api/v1/servers/localhost/tsigkeys" in value:
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

def test_tsigkey_add_success(mock_utils, conditional_mock_utils, example_new_tsigkey):
    get = conditional_mock_utils.mock_http_get()
    post = mock_utils.mock_http_post(201, json_output=example_new_tsigkey)
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_add,
        ['test5', 'hmac-sha256'],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == example_new_tsigkey
    post.assert_called()
    get.assert_called()


def test_tsigkey_name_already_present(mock_utils, conditional_mock_utils, example_new_tsigkey):
    get = conditional_mock_utils.mock_http_get()
    post = mock_utils.mock_http_post(201, json_output=example_new_tsigkey)
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_add,
        ['test1', 'hmac-sha256'],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 0
    assert "already present" in json.loads(result.output)["message"]
    post.assert_not_called()
    get.assert_called()

def test_tsigkey_import_success(mock_utils, conditional_mock_utils, example_new_tsigkey):
    get = conditional_mock_utils.mock_http_get()
    post = mock_utils.mock_http_post(201, json_output=example_new_tsigkey)
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_add,
        ['test5', 'hmac-sha256', "-s", example_new_tsigkey["key"]],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == example_new_tsigkey
    post.assert_called()
    get.assert_called()

def test_tsigkey_import_already_present(mock_utils, conditional_mock_utils, example_tsigkey_test1):
    get = conditional_mock_utils.mock_http_get()
    post = mock_utils.mock_http_post(201, json_output=example_tsigkey_test1)
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_add,
        ['test1', 'hmac-sha256', "-s", example_tsigkey_test1["key"]],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 0
    assert "already present" in json.loads(result.output)["message"]
    post.assert_not_called()
    get.assert_called()

def test_tsigkey_delete_success(mock_utils, conditional_mock_utils):
    get = conditional_mock_utils.mock_http_get()
    delete = mock_utils.mock_http_delete(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_delete,
        ['test1'],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 0
    delete.assert_called()
    get.assert_called()

def test_tsigkey_delete_not_present(mock_utils, conditional_mock_utils):
    get = conditional_mock_utils.mock_http_get()
    delete = mock_utils.mock_http_delete(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_delete,
        ['test5'],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 0
    delete.assert_not_called()
    get.assert_called()

def test_tsigkey_export_success(mock_utils, conditional_mock_utils, example_tsigkey_test1):
    get = conditional_mock_utils.mock_http_get()
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_export,
        ['test1'],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 0
    get.assert_called()
    assert json.loads(result.output) == example_tsigkey_test1

def test_tsigkey_export_fail(mock_utils, conditional_mock_utils, example_tsigkey_test1):
    get = conditional_mock_utils.mock_http_get()
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_export,
        ['test5'],
        obj={'apihost': 'http://example.com'}
    )
    assert "Not found" in json.loads(result.output)["error"]
    assert result.exit_code != 0
    get.assert_called()


def test_tsigkey_list_success(mock_utils, conditional_mock_utils, example_tsigkey_list):
    get = conditional_mock_utils.mock_http_get()
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_list,
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 0
    get.assert_called()
    assert json.loads(result.output) == example_tsigkey_list

def test_tsigkey_list_fail(mock_utils):
    get = mock_utils.mock_http_get(404,json_output={"message": "Not Found"})
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_list,
        obj={'apihost': 'http://example.com'}
    )
    assert json.loads(result.output)["message"] == "Not Found"
    assert result.exit_code != 0
    get.assert_called()

def test_tsigkey_update_success(mock_utils, conditional_mock_utils, example_new_tsigkey):
    get = conditional_mock_utils.mock_http_get()
    put = mock_utils.mock_http_put(200, json_output=example_new_tsigkey)
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_update,
        ["test1", "-s", example_new_tsigkey["key"], "-n", "test5", "-a", "hmac-sha256"],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 0
    get.assert_called()
    put.assert_called()
    assert json.loads(result.output) == example_new_tsigkey

def test_tsigkey_update_item_missing(mock_utils, conditional_mock_utils, example_new_tsigkey):
    get = conditional_mock_utils.mock_http_get()
    put = mock_utils.mock_http_put(200, json_output=example_new_tsigkey)
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_update,
        ["test5", "-s", example_new_tsigkey["key"], "-n", "test5", "-a", "hmac-sha256"],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 1
    get.assert_called()
    put.assert_not_called()
    assert "not exist" in json.loads(result.output)["message"]

def test_tsigkey_update_idempotence(mock_utils, conditional_mock_utils, example_tsigkey_test1):
    get = conditional_mock_utils.mock_http_get()
    put = mock_utils.mock_http_put(200, json_output=example_tsigkey_test1)
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_update,
        ["test1", "-s", example_tsigkey_test1["key"], "-a", "hmac-sha512"],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 0
    get.assert_called()
    put.assert_not_called()
    assert "already" in json.loads(result.output)["message"]

def test_tsigkey_update_refuse_override(mock_utils, conditional_mock_utils, example_tsigkey_test1):
    get = conditional_mock_utils.mock_http_get()
    put = mock_utils.mock_http_put(200, json_output=example_tsigkey_test1)
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_update,
        ["test1", "-n", "test2"],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 1
    get.assert_called()
    put.assert_not_called()
    assert "override" in json.loads(result.output)["message"]

def test_tsigkey_update_rename(mock_utils, conditional_mock_utils, example_tsigkey_test1):
    get = conditional_mock_utils.mock_http_get()
    put = mock_utils.mock_http_put(200, json_output=example_tsigkey_test1)
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_update,
        ["test1", "-n", "test5"],
        obj={'apihost': 'http://example.com'}
    )
    assert result.exit_code == 0
    get.assert_called()
    put.assert_called()
    assert json.loads(result.output) == example_tsigkey_test1
