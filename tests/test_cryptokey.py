import json
import pytest
from click.testing import CliRunner
from powerdns_cli.powerdns_cli import (
    cryptokey_add,
    cryptokey_delete,
    cryptokey_disable,
    cryptokey_enable,
    cryptokey_export,
    cryptokey_list,
)
from powerdns_cli_test_utils import testutils
import requests
from unittest.mock import MagicMock as unittest_MagicMock

class ConditionalMock(testutils.MockUtils):
    def mock_http_get(self) -> unittest_MagicMock:
        def side_effect(*args, **kwargs):
            match args[0]:
                case "https://example.com/api/v1/servers/localhost/zones/example.com./cryptokeys":
                    json_output = example_cryptokey_list
                case "https://example.com/api/v1/servers/localhost/zones/example.com./cryptokeys/1":
                    json_output = example_ksk_key
                case "https://example.com/api/v1/servers/localhost/zones/example.com./cryptokeys/2":
                    json_output = example_zsk_key
                case _:
                    raise NotImplementedError(f"An unexpected url-path was called: {args[0]}")
            mock_http_get = self.mocker.MagicMock(spec=requests.Response)
            mock_http_get.status_code = 200
            mock_http_get.json.return_value = json_output
            mock_http_get.headers = {'Content-Type': 'application/json'}
            return mock_http_get
        return self.mocker.patch('powerdns_cli.utils.http_get', side_effect=side_effect)


@pytest.fixture
def mock_utils(mocker):
    return testutils.MockUtils(mocker)

@pytest.fixture
def conditional_mock_utils(mocker):
    return ConditionalMock(mocker)

example_cryptokey_list = [{"active": True, "algorithm": "ECDSAP256SHA256", "bits": 256, "dnskey": "257 3 13 MvuT0qTd9MaGuK6LXfz7DoT90rMPBNBG8I8J9uikDCJZ7V/8lDE27A6gGnf58SqE39JQbtrMy5q3K1FmFmFkQQ==", "ds": ["17803 13 1 9b0b86483e63a4bb8fe38bb07bd34e78bda8f849", "17803 13 2 78fbd0b96ffefc80f25a67a3aeb85827e865976ef0968e80ba61640afc5fc79f", "17803 13 4 9fdb7071aba84fd104252617bbae15f6e494ca338f6b06bd79c22934cd251148cb65bb38f0f7c49404d9ed4a96281b5a"], "flags": 257, "id": 1, "keytype": "csk", "published": True, "type": "Cryptokey"}, {"active": False, "algorithm": "ED448", "bits": 456, "dnskey": "256 3 16 8zpMKw/T9BuAAGQa1yuKqOSs4oUUcS5rS1pa9Q10nJiTpjB9otYdLMhz3jcOXmhvUy45DroBYpkA", "ds": ["12855 16 1 0c6a746274ab49c3db9ee8f9c57a604779000bf6", "12855 16 2 1998c2e1b55a209a13169b5ae4b1b7b31e81901a068e024dbfdb1c4102381ab1", "12855 16 4 9be187ecb56112b80596ecab8381e5fd1a314614ba0c34b20ef0ff9372f8e26e038a90e25fa3b2d743d0b0e49d577ec9"], "flags": 256, "id": 2, "keytype": "csk", "published": False, "type": "Cryptokey"}]

example_zsk_key = {"active": False, "algorithm": "ED448", "bits": 456, "dnskey": "256 3 16 8zpMKw/T9BuAAGQa1yuKqOSs4oUUcS5rS1pa9Q10nJiTpjB9otYdLMhz3jcOXmhvUy45DroBYpkA", "ds": ["12855 16 1 0c6a746274ab49c3db9ee8f9c57a604779000bf6", "12855 16 2 1998c2e1b55a209a13169b5ae4b1b7b31e81901a068e024dbfdb1c4102381ab1", "12855 16 4 9be187ecb56112b80596ecab8381e5fd1a314614ba0c34b20ef0ff9372f8e26e038a90e25fa3b2d743d0b0e49d577ec9"], "flags": 256, "id": 2, "keytype": "csk", "privatekey": "Private-key-format: v1.2\nAlgorithm: 16 (ED448)\nPrivateKey: Yn5u/wiwM9mGuSMIWcGfCC+UcxMqvcbSWaJo6cHY/AOttPYsp9aqIm5FU1DBaN+Xq2LP3ezi8ZeF\n", "published": False, "type": "Cryptokey"}

example_ksk_key = {"active": True, "algorithm": "ECDSAP256SHA256", "bits": 256, "dnskey": "257 3 13 MvuT0qTd9MaGuK6LXfz7DoT90rMPBNBG8I8J9uikDCJZ7V/8lDE27A6gGnf58SqE39JQbtrMy5q3K1FmFmFkQQ==", "ds": ["17803 13 1 9b0b86483e63a4bb8fe38bb07bd34e78bda8f849", "17803 13 2 78fbd0b96ffefc80f25a67a3aeb85827e865976ef0968e80ba61640afc5fc79f", "17803 13 4 9fdb7071aba84fd104252617bbae15f6e494ca338f6b06bd79c22934cd251148cb65bb38f0f7c49404d9ed4a96281b5a"], "flags": 257, "id": 1, "keytype": "csk", "privatekey": "Private-key-format: v1.2\nAlgorithm: 13 (ECDSAP256SHA256)\nPrivateKey: bcp9l62ibGOhdR6WNLE08MjtdIZNeiLtVBuWT8mp9Ts=\n", "published": True, "type": "Cryptokey"}


def test_cryptokey_add_success(mock_utils):
    get = mock_utils.mock_http_get(200)
    post = mock_utils.mock_http_post(201, json_output={})
    runner = CliRunner()
    result = runner.invoke(
        cryptokey_add,
        ["example.com", "zsk", "--algorithm", "ed448"],
        obj={"apihost": "https://example.com"},
    )
    assert result.exit_code == 0
    get.assert_not_called()
    post.assert_called()


def test_cryptokey_add_already_present(mock_utils, conditional_mock_utils):
    get = conditional_mock_utils.mock_http_get()
    post = mock_utils.mock_http_post(201, json_output={})
    runner = CliRunner()
    result = runner.invoke(
        cryptokey_add,
        ["example.com.", "zsk", "-s", example_zsk_key["privatekey"]],
        obj={"apihost": "https://example.com"},
    )
    assert result.exit_code == 0
    assert "already present" in json.loads(result.output)["message"]
    post.assert_not_called()
    get.assert_called()


# def test_cryptokey_add_failure(mock_utils):
#     get = mock_utils.mock_http_get(404, {"error": "Not found"})
#     post = mock_utils.mock_http_post(500, {"error": "Internal server error"})
#     runner = CliRunner()
#     result = runner.invoke(
#         cryptokey_add,
#         ["example.com.", "zsk", "--bits", "2048", "--algorithm", "rsasha256"],
#         obj={"apihost": "https://example.com"},
#     )
#     assert result.exit_code == 1
#     post.assert_called()
#
#
# def test_cryptokey_delete_success(mock_utils):
#     get = mock_utils.mock_http_get(200, {"id": 1, "type": "zsk", "active": False})
#     delete = mock_utils.mock_http_delete(204, text_output="")
#     runner = CliRunner()
#     result = runner.invoke(
#         cryptokey_delete, ["example.com.", "1"], obj={"apihost": "https://example.com"}
#     )
#     assert result.exit_code == 0
#     assert "deleted" in json.loads(result.output)["message"]
#     delete.assert_called()
#
#
# def test_cryptokey_delete_already_absent(mock_utils):
#     get = mock_utils.mock_http_get(404, {"error": "Not found"})
#     delete = mock_utils.mock_http_delete(204, text_output="")
#     runner = CliRunner()
#     result = runner.invoke(
#         cryptokey_delete, ["example.com.", "1"], obj={"apihost": "https://example.com"}
#     )
#     assert result.exit_code == 0
#     assert "already absent" in json.loads(result.output)["message"]
#     delete.assert_not_called()
#
#
# def test_cryptokey_delete_failure(mock_utils):
#     get = mock_utils.mock_http_get(200, {"id": 1, "type": "zsk", "active": False})
#     delete = mock_utils.mock_http_delete(500, {"error": "Internal server error"})
#     runner = CliRunner()
#     result = runner.invoke(
#         cryptokey_delete, ["example.com.", "1"], obj={"apihost": "https://example.com"}
#     )
#     assert result.exit_code == 1
#     delete.assert_called()
#
#
# def test_cryptokey_disable_success(mock_utils):
#     get = mock_utils.mock_http_get(200, {"id": 1, "type": "zsk", "active": True})
#     put = mock_utils.mock_http_put(204, text_output="")
#     runner = CliRunner()
#     result = runner.invoke(
#         cryptokey_disable, ["example.com.", "1"], obj={"apihost": "https://example.com"}
#     )
#     assert result.exit_code == 0
#     assert "disabled" in json.loads(result.output)["message"]
#     put.assert_called()
#
#
# def test_cryptokey_disable_already_disabled(mock_utils):
#     get = mock_utils.mock_http_get(200, {"id": 1, "type": "zsk", "active": False})
#     put = mock_utils.mock_http_put(204, text_output="")
#     runner = CliRunner()
#     result = runner.invoke(
#         cryptokey_disable, ["example.com.", "1"], obj={"apihost": "http://example.com"}
#     )
#     assert result.exit_code == 0
#     assert "already inactive" in json.loads(result.output)["message"]
#     put.assert_not_called()
#
#
# def test_cryptokey_disable_failure(mock_utils):
#     get = mock_utils.mock_http_get(200, {"id": 1, "type": "zsk", "active": True})
#     put = mock_utils.mock_http_put(500, {"error": "Internal server error"})
#     runner = CliRunner()
#     result = runner.invoke(
#         cryptokey_disable, ["example.com.", "1"], obj={"apihost": "http://example.com"}
#     )
#     assert result.exit_code == 1
#     put.assert_called()
#
#
# def test_cryptokey_enable_success(mock_utils):
#     get = mock_utils.mock_http_get(200, {"id": 1, "type": "zsk", "active": False})
#     put = mock_utils.mock_http_put(204, text_output="")
#     runner = CliRunner()
#     result = runner.invoke(
#         cryptokey_enable, ["example.com.", "1"], obj={"apihost": "http://example.com"}
#     )
#     assert result.exit_code == 0
#     assert "enabled" in json.loads(result.output)["message"]
#     put.assert_called()
#
#
# def test_cryptokey_enable_already_enabled(mock_utils):
#     get = mock_utils.mock_http_get(200, {"id": 1, "type": "zsk", "active": True})
#     put = mock_utils.mock_http_put(204, text_output="")
#     runner = CliRunner()
#     result = runner.invoke(
#         cryptokey_enable, ["example.com.", "1"], obj={"apihost": "http://example.com"}
#     )
#     assert result.exit_code == 0
#     assert "already active" in json.loads(result.output)["message"]
#     put.assert_not_called()
#
#
# def test_cryptokey_enable_failure(mock_utils):
#     get = mock_utils.mock_http_get(200, {"id": 1, "type": "zsk", "active": False})
#     put = mock_utils.mock_http_put(500, {"error": "Internal server error"})
#     runner = CliRunner()
#     result = runner.invoke(
#         cryptokey_enable, ["example.com.", "1"], obj={"apihost": "http://example.com"}
#     )
#     assert result.exit_code == 1
#     put.assert_called()
#
#
# def test_cryptokey_export_success(mock_utils):
#     get = mock_utils.mock_http_get(
#         200, {"id": 1, "type": "zsk", "active": False, "key": "secret"}
#     )
#     runner = CliRunner()
#     result = runner.invoke(
#         cryptokey_export, ["example.com.", "1"], obj={"apihost": "http://example.com"}
#     )
#     assert result.exit_code == 0
#     get.assert_called()
#
#
# def test_cryptokey_export_not_found(mock_utils):
#     get = mock_utils.mock_http_get(404, {"error": "Not found"})
#     runner = CliRunner()
#     result = runner.invoke(
#         cryptokey_export, ["example.com.", "1"], obj={"apihost": "http://example.com"}
#     )
#     assert result.exit_code == 1
#     get.assert_called()
#
#
# def test_cryptokey_export_failure(mock_utils):
#     get = mock_utils.mock_http_get(500, {"error": "Internal server error"})
#     runner = CliRunner()
#     result = runner.invoke(
#         cryptokey_export, ["example.com.", "1"], obj={"apihost": "http://example.com"}
#     )
#     assert result.exit_code == 1
#     get.assert_called()
#
#
# def test_cryptokey_list_success(mock_utils):
#     get = mock_utils.mock_http_get(200, [{"id": 1, "type": "zsk", "active": False}])
#     runner = CliRunner()
#     result = runner.invoke(
#         cryptokey_list, ["example.com."], obj={"apihost": "http://example.com"}
#     )
#     assert result.exit_code == 0
#     get.assert_called()
#
#
# def test_cryptokey_list_failure(mock_utils):
#     get = mock_utils.mock_http_get(500, {"error": "Internal server error"})
#     runner = CliRunner()
#     result = runner.invoke(
#         cryptokey_list, ["example.com."], obj={"apihost": "http://example.com"}
#     )
#     assert result.exit_code == 1
#     get.assert_called()
