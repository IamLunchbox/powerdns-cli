import copy
import json
from typing import NamedTuple
from unittest.mock import MagicMock

import pytest
import requests
from click.testing import CliRunner
from powerdns_cli_test_utils import testutils
from powerdns_cli_test_utils.testutils import mock_utils, testenvironment, testobject

from powerdns_cli.commands.tsigkey import (
    tsigkey_add,
    tsigkey_delete,
    tsigkey_export,
    tsigkey_import,
    tsigkey_list,
    tsigkey_update,
)


@pytest.fixture
def conditional_mock_utils(mocker):
    return ConditionalMock(mocker)


example_new_tsigkey_dict = {
    "algorithm": "hmac-sha256",
    "id": "test.",
    "key": "AvyIiTEIaHxfwHsif+0Z39cxTra8P8KcyPpMNQdANzHgm73rvXPFqZbgmPolE6jWEKYrM5KruSJyuoAoCpY8Nw==",
    "name": "test",
    "type": "TSIGKey",
}


@pytest.fixture
def example_new_tsigkey():
    return copy.deepcopy(example_new_tsigkey_dict)


example_tsigkey_test_1_dict = {
    "algorithm": "hmac-sha512",
    "id": "test1.",
    "key": "WRoq4mEXTRAYMchV6/YfOWwHR5hdJ9zgWlIm0bVgrX9BoYIsLjy6jErVThBUrCffguQo2W+sHri7h9h8CaHlag==",
    "name": "test1",
    "type": "TSIGKey",
}


@pytest.fixture
def example_tsigkey_test1():
    return copy.deepcopy(example_tsigkey_test_1_dict)


example_tsigkey_test_2_dict = {
    "algorithm": "hmac-sha384",
    "id": "test2.",
    "key": "yZYHOEtBoYuRaN0Qwn9Z21EQ7FwQLzmbal7PLTJKNwL0Ql3Yiaxnk8+RV6lZNvxiBeZQqHlw1uEUj1l7IX7mhA==",
    "name": "test2",
    "type": "TSIGKey",
}


@pytest.fixture
def example_tsigkey_test2():
    return copy.deepcopy(example_tsigkey_test_2_dict)


example_tsigkey_list_list = [
    {"algorithm": "hmac-sha512", "id": "test1.", "key": "", "name": "test1", "type": "TSIGKey"},
    {"algorithm": "hmac-sha384", "id": "test2.", "key": "", "name": "test2", "type": "TSIGKey"},
]


@pytest.fixture
def example_tsigkey_list():
    return copy.deepcopy(example_tsigkey_list_list)


@pytest.fixture
def file_mock(mocker):
    return testutils.MockFile(mocker)


class ConditionalMock(testutils.MockUtils):
    def mock_http_get(self) -> MagicMock:
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
            mock_http_get.headers = {"Content-Type": "application/json"}
            return mock_http_get

        return self.mocker.patch("powerdns_cli.utils.main.http_get", side_effect=side_effect)


def test_tsigkey_add_success(mock_utils, testobject, conditional_mock_utils, example_new_tsigkey):
    get = conditional_mock_utils.mock_http_get()
    post = mock_utils.mock_http_post(201, json_output=example_new_tsigkey)
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_add,
        ["test5", "hmac-sha256"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert json.loads(result.output)["data"] == example_new_tsigkey
    post.assert_called()
    get.assert_called()


def test_tsigkey_add_already_present(
    mock_utils, testobject, conditional_mock_utils, example_new_tsigkey
):
    get = conditional_mock_utils.mock_http_get()
    post = mock_utils.mock_http_post(201, json_output=example_new_tsigkey)
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_add,
        ["test1", "hmac-sha256"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "already present" in json.loads(result.output)["message"]
    post.assert_not_called()
    get.assert_called()


def test_tsigkey_add_privatekey_success(
    mock_utils, testobject, conditional_mock_utils, example_new_tsigkey
):
    get = conditional_mock_utils.mock_http_get()
    post = mock_utils.mock_http_post(201, json_output=example_new_tsigkey)
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_add,
        ["test5", "hmac-sha256", "-s", example_new_tsigkey["key"]],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert json.loads(result.output)["data"] == example_new_tsigkey
    post.assert_called()
    get.assert_called()


def test_tsigkey_add_privatekey_already_present(
    mock_utils, testobject, conditional_mock_utils, example_tsigkey_test1
):
    get = conditional_mock_utils.mock_http_get()
    post = mock_utils.mock_http_post(201, json_output=example_tsigkey_test1)
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_add,
        ["test1", "hmac-sha256", "-s", example_tsigkey_test1["key"]],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "already present" in json.loads(result.output)["message"]
    post.assert_not_called()
    get.assert_called()


def test_tsigkey_delete_success(mock_utils, testobject, conditional_mock_utils):
    get = conditional_mock_utils.mock_http_get()
    delete = mock_utils.mock_http_delete(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_delete,
        ["test1"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    delete.assert_called()
    get.assert_called()


def test_tsigkey_delete_not_present(mock_utils, testobject, conditional_mock_utils):
    get = conditional_mock_utils.mock_http_get()
    delete = mock_utils.mock_http_delete(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_delete,
        ["test5"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    delete.assert_not_called()
    get.assert_called()


def test_tsigkey_export_success(
    mock_utils, testobject, conditional_mock_utils, example_tsigkey_test1
):
    get = conditional_mock_utils.mock_http_get()
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_export,
        ["test1"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    get.assert_called()
    assert json.loads(result.output)["data"] == example_tsigkey_test1


def test_tsigkey_export_fail(mock_utils, testobject, conditional_mock_utils, example_tsigkey_test1):
    get = conditional_mock_utils.mock_http_get()
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_export,
        ["test5"],
        obj=testobject,
        env=testenvironment,
    )
    assert "Failed" in json.loads(result.output)["message"]
    assert result.exit_code != 0
    get.assert_called()


class TsigkeyImport(NamedTuple):
    file_contents: list[dict]
    upstream_content: list[dict]
    added_content: list[dict]
    delete_path: list[str]


testcase = (
    TsigkeyImport(
        file_contents=[
            {
                "algorithm": "hmac-md5",
                "id": "test.",
                "key": "Rx+i3J/OWPCiJ9fE3n1Ph3tc8uQgWXztaiTWP9WdrjQ=",
                "name": "test",
                "type": "TSIGKey",
            }
        ],
        upstream_content=[],
        added_content=[
            {
                "algorithm": "hmac-md5",
                "id": "test.",
                "key": "Rx+i3J/OWPCiJ9fE3n1Ph3tc8uQgWXztaiTWP9WdrjQ=",
                "name": "test",
                "type": "TSIGKey",
            }
        ],
        delete_path=[],
    ),
    TsigkeyImport(
        file_contents=[
            {
                "algorithm": "hmac-md5",
                "id": "test.",
                "key": "Rx+i3J/OWPCiJ9fE3n1Ph3tc8uQgWXztaiTWP9WdrjQ=",
                "name": "test",
                "type": "TSIGKey",
            },
            {
                "algorithm": "hmac-sha256",
                "id": "test123.",
                "key": "y9Hd0SFxHvY0YRrznu06MrpXgDoRzwnnkNCOpf19+3BxAX8oIWFCejK31lmMV9ouuUtr6VXMpTXycJCsXuMmAA==",
                "name": "test123",
                "type": "TSIGKey",
            },
        ],
        upstream_content=[
            {
                "algorithm": "hmac-sha256",
                "id": "test123.",
                "key": "y9Hd0SFxHvY0YRrznu06MrpXgDoRzwnnkNCOpf19+3BxAX8oIWFCejK31lmMV9ouuUtr6VXMpTXycJCsXuMmAA==",
                "name": "test123",
                "type": "TSIGKey",
            },
            {
                "algorithm": "hmac-sha512",
                "id": "test321.",
                "key": "bNGwwOeyX3c9TKwY5sKszW5l2gv1I5EpQ5s8o68jiG8ymEr489xL/jlLrlWZSG54u61Tmo8ftj68Tfbodh9NnA==",
                "name": "test321",
                "type": "TSIGKey",
            },
        ],
        added_content=[
            {
                "algorithm": "hmac-md5",
                "id": "test.",
                "key": "Rx+i3J/OWPCiJ9fE3n1Ph3tc8uQgWXztaiTWP9WdrjQ=",
                "name": "test",
                "type": "TSIGKey",
            },
            {
                "algorithm": "hmac-sha256",
                "id": "test123.",
                "key": "y9Hd0SFxHvY0YRrznu06MrpXgDoRzwnnkNCOpf19+3BxAX8oIWFCejK31lmMV9ouuUtr6VXMpTXycJCsXuMmAA==",
                "name": "test123",
                "type": "TSIGKey",
            },
        ],
        delete_path=[],
    ),
)


@pytest.mark.parametrize("file_contents, upstream_content, added_content, delete_path", testcase)
def test_tsigkey_import_success(
    mocker,
    mock_utils,
    testobject,
    file_mock,
    file_contents,
    upstream_content,
    added_content,
    delete_path,
):
    file_mock.mock_settings_import(file_contents)
    mocker.patch(
        "powerdns_cli.commands.tsigkey.get_tsigkey_settings", return_value=upstream_content
    )
    post = mock_utils.mock_http_post(201, json_output={"message": "OK"})
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_import,
        ["testfile"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "Successfully" in json.loads(result.output)["message"]
    post.assert_called()
    for item in added_content:
        assert item in [request.kwargs["payload"] for request in post.call_args_list]


testcase_idempotence = (
    TsigkeyImport(
        file_contents=[
            {
                "algorithm": "hmac-md5",
                "id": "test.",
                "key": "Rx+i3J/OWPCiJ9fE3n1Ph3tc8uQgWXztaiTWP9WdrjQ=",
                "name": "test",
                "type": "TSIGKey",
            }
        ],
        upstream_content=[
            {
                "algorithm": "hmac-md5",
                "id": "test.",
                "key": "Rx+i3J/OWPCiJ9fE3n1Ph3tc8uQgWXztaiTWP9WdrjQ=",
                "name": "test",
                "type": "TSIGKey",
            }
        ],
        added_content=[],
        delete_path=[],
    ),
    TsigkeyImport(
        file_contents=[
            {
                "algorithm": "hmac-md5",
                "id": "test.",
                "key": "Rx+i3J/OWPCiJ9fE3n1Ph3tc8uQgWXztaiTWP9WdrjQ=",
                "name": "test",
                "type": "TSIGKey",
            }
        ],
        upstream_content=[
            {
                "algorithm": "hmac-md5",
                "id": "test.",
                "key": "Rx+i3J/OWPCiJ9fE3n1Ph3tc8uQgWXztaiTWP9WdrjQ=",
                "name": "test",
                "type": "TSIGKey",
            }
        ],
        added_content=[],
        delete_path=[],
    ),
    TsigkeyImport(
        file_contents=[],
        upstream_content=[
            {
                "algorithm": "hmac-sha256",
                "id": "test123.",
                "key": "y9Hd0SFxHvY0YRrznu06MrpXgDoRzwnnkNCOpf19+3BxAX8oIWFCejK31lmMV9ouuUtr6VXMpTXycJCsXuMmAA==",
                "name": "test123",
                "type": "TSIGKey",
            },
            {
                "algorithm": "hmac-sha512",
                "id": "test321.",
                "key": "bNGwwOeyX3c9TKwY5sKszW5l2gv1I5EpQ5s8o68jiG8ymEr489xL/jlLrlWZSG54u61Tmo8ftj68Tfbodh9NnA==",
                "name": "test321",
                "type": "TSIGKey",
            },
            {
                "algorithm": "hmac-md5",
                "id": "test.",
                "key": "Rx+i3J/OWPCiJ9fE3n1Ph3tc8uQgWXztaiTWP9WdrjQ=",
                "name": "test",
                "type": "TSIGKey",
            },
        ],
        added_content=[],
        delete_path=[],
    ),
)


@pytest.mark.parametrize(
    "file_contents, upstream_content, added_content, delete_path", testcase_idempotence
)
def test_tsigkey_import_idempotence(
    mocker,
    mock_utils,
    testobject,
    file_mock,
    file_contents,
    upstream_content,
    added_content,
    delete_path,
):
    file_mock.mock_settings_import(file_contents)
    mocker.patch(
        "powerdns_cli.commands.tsigkey.get_tsigkey_settings", return_value=upstream_content
    )
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_import,
        ["testfile"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "already" in json.loads(result.output)["message"]


def test_tsigkey_import_failed(mocker, mock_utils, testobject, file_mock):
    file_mock.mock_settings_import(
        [
            {
                "algorithm": "hmac-md5",
                "id": "test.",
                "key": "Rx+i3J/OWPCiJ9fE3n1Ph3tc8uQgWXztaiTWP9WdrjQ=",
                "name": "test",
                "type": "TSIGKey",
            },
            {
                "algorithm": "hmac-sha256",
                "id": "test123.",
                "key": "y9Hd0SFxHvY0YRrznu06MrpXgDoRzwnnkNCOpf19+3BxAX8oIWFCejK31lmMV9ouuUtr6VXMpTXycJCsXuMmAA==",
                "name": "test123",
                "type": "TSIGKey",
            },
        ]
    )
    mocker.patch(
        "powerdns_cli.commands.tsigkey.get_tsigkey_settings",
        return_value=[
            {
                "algorithm": "hmac-sha512",
                "id": "test321.",
                "key": "bNGwwOeyX3c9TKwY5sKszW5l2gv1I5EpQ5s8o68jiG8ymEr489xL/jlLrlWZSG54u61Tmo8ftj68Tfbodh9NnA==",
                "name": "test321",
                "type": "TSIGKey",
            },
        ],
    )
    post = mock_utils.mock_http_post(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_import,
        ["testfile"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    assert "Failed" in json.loads(result.output)["message"]
    post.assert_called_once()


def test_tsigkey_import_ignore_errors(mocker, mock_utils, testobject, file_mock):
    file_mock.mock_settings_import(
        [
            {
                "algorithm": "hmac-md5",
                "id": "test.",
                "key": "Rx+i3J/OWPCiJ9fE3n1Ph3tc8uQgWXztaiTWP9WdrjQ=",
                "name": "test",
                "type": "TSIGKey",
            },
            {
                "algorithm": "hmac-sha256",
                "id": "test123.",
                "key": "y9Hd0SFxHvY0YRrznu06MrpXgDoRzwnnkNCOpf19+3BxAX8oIWFCejK31lmMV9ouuUtr6VXMpTXycJCsXuMmAA==",
                "name": "test123",
                "type": "TSIGKey",
            },
        ]
    )
    mocker.patch(
        "powerdns_cli.commands.tsigkey.get_tsigkey_settings",
        return_value=[
            {
                "algorithm": "hmac-sha512",
                "id": "test321.",
                "key": "bNGwwOeyX3c9TKwY5sKszW5l2gv1I5EpQ5s8o68jiG8ymEr489xL/jlLrlWZSG54u61Tmo8ftj68Tfbodh9NnA==",
                "name": "test321",
                "type": "TSIGKey",
            },
        ],
    )
    post = mock_utils.mock_http_post(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_import,
        ["testfile", "--ignore-errors"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "Successfully" in json.loads(result.stdout)["message"]
    assert len(post.call_args_list) == 2


testcase_replace = (
    TsigkeyImport(
        file_contents=[
            {
                "algorithm": "hmac-md5",
                "id": "test.",
                "key": "Rx+i3J/OWPCiJ9fE3n1Ph3tc8uQgWXztaiTWP9WdrjQ=",
                "name": "test",
                "type": "TSIGKey",
            },
            {
                "algorithm": "hmac-sha256",
                "id": "test123.",
                "key": "y9Hd0SFxHvY0YRrznu06MrpXgDoRzwnnkNCOpf19+3BxAX8oIWFCejK31lmMV9ouuUtr6VXMpTXycJCsXuMmAA==",
                "name": "test123",
                "type": "TSIGKey",
            },
        ],
        upstream_content=[
            {
                "algorithm": "hmac-sha256",
                "id": "test123.",
                "key": "y9Hd0SFxHvY0YRrznu06MrpXgDoRzwnnkNCOpf19+3BxAX8oIWFCejK31lmMV9ouuUtr6VXMpTXycJCsXuMmAA==",
                "name": "test123",
                "type": "TSIGKey",
            },
            {
                "algorithm": "hmac-sha512",
                "id": "test321.",
                "key": "bNGwwOeyX3c9TKwY5sKszW5l2gv1I5EpQ5s8o68jiG8ymEr489xL/jlLrlWZSG54u61Tmo8ftj68Tfbodh9NnA==",
                "name": "test321",
                "type": "TSIGKey",
            },
        ],
        added_content=[
            {
                "algorithm": "hmac-md5",
                "id": "test.",
                "key": "Rx+i3J/OWPCiJ9fE3n1Ph3tc8uQgWXztaiTWP9WdrjQ=",
                "name": "test",
                "type": "TSIGKey",
            },
        ],
        delete_path=["http://example.com/api/v1/servers/localhost/tsigkeys/test321"],
    ),
    TsigkeyImport(
        file_contents=[],
        upstream_content=[
            {
                "algorithm": "hmac-sha256",
                "id": "test123.",
                "key": "y9Hd0SFxHvY0YRrznu06MrpXgDoRzwnnkNCOpf19+3BxAX8oIWFCejK31lmMV9ouuUtr6VXMpTXycJCsXuMmAA==",
                "name": "test123",
                "type": "TSIGKey",
            },
            {
                "algorithm": "hmac-sha512",
                "id": "test321.",
                "key": "bNGwwOeyX3c9TKwY5sKszW5l2gv1I5EpQ5s8o68jiG8ymEr489xL/jlLrlWZSG54u61Tmo8ftj68Tfbodh9NnA==",
                "name": "test321",
                "type": "TSIGKey",
            },
        ],
        added_content=[],
        delete_path=[
            "http://example.com/api/v1/servers/localhost/tsigkeys/test321",
            "http://example.com/api/v1/servers/localhost/tsigkeys/test123",
        ],
    ),
)


@pytest.mark.parametrize(
    "file_contents, upstream_content, added_content, delete_path", testcase_replace
)
def test_tsigkey_import_replace(
    mocker,
    mock_utils,
    testobject,
    file_mock,
    file_contents,
    upstream_content,
    added_content,
    delete_path,
):
    file_mock.mock_settings_import(file_contents)
    mocker.patch(
        "powerdns_cli.commands.tsigkey.get_tsigkey_settings", return_value=upstream_content
    )
    post = mock_utils.mock_http_post(201, json_output={"message": "OK"})
    delete = mock_utils.mock_http_delete(204, json_output={"message": "OK"})
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_import,
        ["testfile", "--replace"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "Successfully" in json.loads(result.output)["message"]
    assert len(added_content) == len(post.call_args_list)
    for item in added_content:
        assert item in [request.kwargs["payload"] for request in post.call_args_list]
    assert len(delete_path) == len(delete.call_args_list)
    for item in delete_path:
        delete.assert_called()
        assert item in [request.args[0] for request in delete.call_args_list]


def test_tsigkey_import_replace_failed(mocker, mock_utils, testobject, file_mock):
    file_mock.mock_settings_import(
        [
            {
                "algorithm": "hmac-md5",
                "id": "test.",
                "key": "Rx+i3J/OWPCiJ9fE3n1Ph3tc8uQgWXztaiTWP9WdrjQ=",
                "name": "test",
                "type": "TSIGKey",
            },
            {
                "algorithm": "hmac-sha256",
                "id": "test123.",
                "key": "y9Hd0SFxHvY0YRrznu06MrpXgDoRzwnnkNCOpf19+3BxAX8oIWFCejK31lmMV9ouuUtr6VXMpTXycJCsXuMmAA==",
                "name": "test123",
                "type": "TSIGKey",
            },
        ]
    )
    mocker.patch(
        "powerdns_cli.commands.tsigkey.get_tsigkey_settings",
        return_value=[
            {
                "algorithm": "hmac-sha512",
                "id": "test321.",
                "key": "bNGwwOeyX3c9TKwY5sKszW5l2gv1I5EpQ5s8o68jiG8ymEr489xL/jlLrlWZSG54u61Tmo8ftj68Tfbodh9NnA==",
                "name": "test321",
                "type": "TSIGKey",
            },
        ],
    )
    post = mock_utils.mock_http_post(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_import,
        ["testfile", "--replace"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    assert "Failed" in json.loads(result.output)["message"]
    post.assert_called_once()


@pytest.mark.parametrize(
    "post_code,delete_code,post_calls,delete_calls", ((500, 100, 1, 0), (201, 500, 2, 1))
)
def test_tsigkey_import_replace_early_exit(
    mocker, mock_utils, testobject, file_mock, post_code, delete_code, post_calls, delete_calls
):
    file_mock.mock_settings_import(
        [
            {
                "algorithm": "hmac-md5",
                "id": "test.",
                "key": "Rx+i3J/OWPCiJ9fE3n1Ph3tc8uQgWXztaiTWP9WdrjQ=",
                "name": "test",
                "type": "TSIGKey",
            },
            {
                "algorithm": "hmac-sha256",
                "id": "test123.",
                "key": "y9Hd0SFxHvY0YRrznu06MrpXgDoRzwnnkNCOpf19+3BxAX8oIWFCejK31lmMV9ouuUtr6VXMpTXycJCsXuMmAA==",
                "name": "test123",
                "type": "TSIGKey",
            },
        ]
    )
    mocker.patch(
        "powerdns_cli.commands.tsigkey.get_tsigkey_settings",
        return_value=[
            {
                "algorithm": "hmac-sha512",
                "id": "test321.",
                "key": "bNGwwOeyX3c9TKwY5sKszW5l2gv1I5EpQ5s8o68jiG8ymEr489xL/jlLrlWZSG54u61Tmo8ftj68Tfbodh9NnA==",
                "name": "test321",
                "type": "TSIGKey",
            },
            {
                "algorithm": "hmac-sha512",
                "id": "example.",
                "key": "6bcFDLazAzbRZKKOsDT7vHXxfMjwcba+S2/QZncO8gtoAs5aBfFiQDj4kSBUEkmLcSs/HWtlR3Ri0ktBGxDGmQ==",
                "name": "example",
                "type": "TSIGKey",
            },
        ],
    )
    post = mock_utils.mock_http_post(post_code, json_output={"error": "Server error"})
    delete = mock_utils.mock_http_delete(delete_code, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_import,
        ["testfile", "--replace"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    assert "Failed" in json.loads(result.output)["message"]
    assert post_calls == len(post.call_args_list)
    assert delete_calls == len(delete.call_args_list)


@pytest.mark.parametrize("post_code,delete_code", ((500, 204), (201, 500)))
def test_tsigkey_import_replace_ignore_errors(
    mocker, mock_utils, testobject, file_mock, post_code, delete_code
):
    file_mock.mock_settings_import(
        [
            {
                "algorithm": "hmac-md5",
                "id": "test.",
                "key": "Rx+i3J/OWPCiJ9fE3n1Ph3tc8uQgWXztaiTWP9WdrjQ=",
                "name": "test",
                "type": "TSIGKey",
            },
            {
                "algorithm": "hmac-sha256",
                "id": "test123.",
                "key": "y9Hd0SFxHvY0YRrznu06MrpXgDoRzwnnkNCOpf19+3BxAX8oIWFCejK31lmMV9ouuUtr6VXMpTXycJCsXuMmAA==",
                "name": "test123",
                "type": "TSIGKey",
            },
        ]
    )
    mocker.patch(
        "powerdns_cli.commands.tsigkey.get_tsigkey_settings",
        return_value=[
            {
                "algorithm": "hmac-sha512",
                "id": "test321.",
                "key": "bNGwwOeyX3c9TKwY5sKszW5l2gv1I5EpQ5s8o68jiG8ymEr489xL/jlLrlWZSG54u61Tmo8ftj68Tfbodh9NnA==",
                "name": "test321",
                "type": "TSIGKey",
            },
            {
                "algorithm": "hmac-sha512",
                "id": "example.",
                "key": "6bcFDLazAzbRZKKOsDT7vHXxfMjwcba+S2/QZncO8gtoAs5aBfFiQDj4kSBUEkmLcSs/HWtlR3Ri0ktBGxDGmQ==",
                "name": "example",
                "type": "TSIGKey",
            },
        ],
    )
    post = mock_utils.mock_http_post(post_code, json_output={"error": "Server error"})
    delete = mock_utils.mock_http_delete(delete_code, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_import,
        ["testfile", "--replace", "--ignore-errors"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "Successfully" in json.loads(result.output)["message"]
    assert 2 == len(post.call_args_list)
    assert 2 == len(delete.call_args_list)


testcase_replace_idempotence = (
    TsigkeyImport(
        file_contents=[
            {
                "algorithm": "hmac-md5",
                "id": "test.",
                "key": "Rx+i3J/OWPCiJ9fE3n1Ph3tc8uQgWXztaiTWP9WdrjQ=",
                "name": "test",
                "type": "TSIGKey",
            }
        ],
        upstream_content=[
            {
                "algorithm": "hmac-md5",
                "id": "test.",
                "key": "Rx+i3J/OWPCiJ9fE3n1Ph3tc8uQgWXztaiTWP9WdrjQ=",
                "name": "test",
                "type": "TSIGKey",
            }
        ],
        added_content=[],
        delete_path=[],
    ),
    TsigkeyImport(
        file_contents=[],
        upstream_content=[],
        added_content=[],
        delete_path=[],
    ),
)


@pytest.mark.parametrize(
    "file_contents, upstream_content, added_content, delete_path", testcase_replace_idempotence
)
def test_tsigkey_import_replace_idempotence(
    mocker,
    mock_utils,
    testobject,
    file_mock,
    file_contents,
    upstream_content,
    added_content,
    delete_path,
):
    file_mock.mock_settings_import(file_contents)
    mocker.patch(
        "powerdns_cli.commands.tsigkey.get_tsigkey_settings", return_value=upstream_content
    )
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_import,
        ["testfile", "--replace"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "already" in json.loads(result.output)["message"]


def test_tsigkey_list_success(mock_utils, testobject, conditional_mock_utils, example_tsigkey_list):
    get = conditional_mock_utils.mock_http_get()
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_list,
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    get.assert_called()
    assert json.loads(result.output)["data"] == example_tsigkey_list


def test_tsigkey_list_fail(mock_utils, testobject):
    get = mock_utils.mock_http_get(404, json_output={"message": "Not Found"})
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_list,
        obj=testobject,
        env=testenvironment,
    )
    assert "Failed" in json.loads(result.output)["message"]
    assert result.exit_code != 0
    get.assert_called()


def test_tsigkey_update_success(
    mock_utils, testobject, conditional_mock_utils, example_new_tsigkey
):
    get = conditional_mock_utils.mock_http_get()
    put = mock_utils.mock_http_put(200, json_output=example_new_tsigkey)
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_update,
        ["test1", "-s", example_new_tsigkey["key"], "-n", "test5", "-a", "hmac-sha256"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    get.assert_called()
    put.assert_called()
    assert json.loads(result.output)["data"] == example_new_tsigkey


def test_tsigkey_update_item_missing(
    mock_utils, testobject, conditional_mock_utils, example_new_tsigkey
):
    get = conditional_mock_utils.mock_http_get()
    put = mock_utils.mock_http_put(200, json_output=example_new_tsigkey)
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_update,
        ["test5", "-s", example_new_tsigkey["key"], "-n", "test5", "-a", "hmac-sha256"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    get.assert_called()
    put.assert_not_called()
    assert "not exist" in json.loads(result.output)["message"]


def test_tsigkey_update_idempotence(
    mock_utils, testobject, conditional_mock_utils, example_tsigkey_test1
):
    get = conditional_mock_utils.mock_http_get()
    put = mock_utils.mock_http_put(200, json_output=example_tsigkey_test1)
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_update,
        ["test1", "-s", example_tsigkey_test1["key"], "-a", "hmac-sha512"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    get.assert_called()
    put.assert_not_called()
    assert "already" in json.loads(result.output)["message"]


def test_tsigkey_update_refuse_rewrite(
    mock_utils, testobject, conditional_mock_utils, example_tsigkey_test1
):
    get = conditional_mock_utils.mock_http_get()
    put = mock_utils.mock_http_put(200, json_output=example_tsigkey_test1)
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_update,
        ["test1", "-n", "test2"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    get.assert_called()
    put.assert_not_called()
    assert "Refusing" in json.loads(result.output)["message"]


def test_tsigkey_update_rename(
    mock_utils, testobject, conditional_mock_utils, example_tsigkey_test1
):
    get = conditional_mock_utils.mock_http_get()
    put = mock_utils.mock_http_put(200, json_output=example_tsigkey_test1)
    runner = CliRunner()
    result = runner.invoke(
        tsigkey_update,
        ["test1", "-n", "test5"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    get.assert_called()
    put.assert_called()
    assert json.loads(result.output)["data"] == example_tsigkey_test1
