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
        # TODO: Add status codes to return
        def side_effect(*args, **kwargs):
            match args[0]:
                case "https://example.com/api/v1/servers/localhost/tsigkeys":
                    json_output = example_tsigkey_list_list
                case "https://example.com/api/v1/servers/localhost/tsigkeys/test1":
                    json_output = example_tsigkey_test_1_dict
                case "https://example.com/api/v1/servers/localhost/tsigkeys/test2":
                    json_output = example_tsigkey_test_2_dict
                case _:
                    raise NotImplementedError(f"An unexpected url-path was called: {args[0]}")
            mock_http_get = self.mocker.MagicMock(spec=requests.Response)
            mock_http_get.status_code = 200
            mock_http_get.json.return_value = json_output
            mock_http_get.headers = {'Content-Type': 'application/json'}
            return mock_http_get
        return self.mocker.patch('powerdns_cli.utils.http_get', side_effect=side_effect)


def test_tsigkey_add_success(mock_utils, example_new_tsigkey):
    # TODO: dont pass status code here but rather at the side effect level
    get = mock_utils.mock_http_get(404)
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


# def test_tsigkey_add_already_present(mock_utils):
#     get = mock_utils.mock_http_get(200, {'name': 'example-key'})
#     post = mock_utils.mock_http_post(201, text_output='')
#     runner = CliRunner()
#     result = runner.invoke(
#         tsigkey_add,
#         ['example-key', 'hmac-sha256', '--secret', 'secret'],
#         obj={'apihost': 'http://example.com'}
#     )
#     assert result.exit_code == 0
#     assert 'already present' in json.loads(result.output)['message']
#     post.assert_not_called()
#
#
# def test_tsigkey_add_failure(mock_utils):
#     get = mock_utils.mock_http_get(404, {'error': 'Not found'})
#     post = mock_utils.mock_http_post(500, {'error': 'Internal server error'})
#     runner = CliRunner()
#     result = runner.invoke(
#         tsigkey_add,
#         ['example-key', 'hmac-sha256', '--secret', 'secret'],
#         obj={'apihost': 'http://example.com'}
#     )
#     assert result.exit_code == 1

