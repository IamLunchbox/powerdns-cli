import copy
import json
from typing import NamedTuple
from unittest.mock import MagicMock

import pytest
import requests
from click.testing import CliRunner
from powerdns_cli_test_utils import testutils
from powerdns_cli_test_utils.testutils import mock_utils, testenvironment, testobject

from powerdns_cli.commands.metadata import (
    metadata_add,
    metadata_delete,
    metadata_export,
    metadata_extend,
    metadata_import,
    metadata_update,
)


@pytest.fixture
def conditional_mock_utils(mocker):
    return ConditionalMock(mocker)


example_metadata_list = [
    {"kind": "SOA-EDIT-API", "metadata": ["DEFAULT"], "type": "Metadata"},
    {"kind": "ALSO-NOTIFY", "metadata": ["192.0.2.1:5305", "192.0.2.2:5305"], "type": "Metadata"},
]


@pytest.fixture
def example_metadata():
    return copy.deepcopy(example_metadata_list)


example_soa_edit_api_dict = {"kind": "SOA-EDIT-API", "metadata": ["DEFAULT"], "type": "Metadata"}


@pytest.fixture
def example_soa_edit_api():
    return copy.deepcopy(example_soa_edit_api_dict)


example_also_notify_dict = {
    "kind": "ALSO-NOTIFY",
    "metadata": ["192.0.2.1:5305", "192.0.2.2:5305"],
    "type": "Metadata",
}


@pytest.fixture
def example_also_notify():
    return copy.deepcopy(example_also_notify_dict)


example_new_data_dict = {"kind": "X-NEW-DATA", "metadata": ["test123"], "type": "Metadata"}


@pytest.fixture
def example_new_data():
    return copy.deepcopy(example_new_data_dict)


@pytest.fixture
def file_mock(mocker):
    return testutils.MockFile(mocker)


class ConditionalMock(testutils.MockUtils):
    def mock_http_get(self) -> MagicMock:
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
                case "http://example.com/api/v1/servers/localhost/zones/example.com./metadata/X-NEW-DATA":
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


class ExitCodes(NamedTuple):
    http_get_code: int
    http_post_code: int
    http_delete_code: int


class TC(NamedTuple):
    file_contents: list[dict[str, str]]
    upstream_content: list[dict[str, str]]
    added_content: list[dict[str, str]]
    delete_paths: list[str]


def test_metadata_add_success(mock_utils, testobject, conditional_mock_utils, example_new_data):
    get = conditional_mock_utils.mock_http_get()
    post = mock_utils.mock_http_post(201, json_output=example_new_data)
    runner = CliRunner()
    result = runner.invoke(
        metadata_add,
        ["example.com", example_new_data["kind"], example_new_data["metadata"][0]],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert json.loads(result.output)["data"] == example_new_data
    post.assert_called()
    get.assert_called()


def test_metadata_add_idempotence(
    mock_utils, testobject, conditional_mock_utils, example_soa_edit_api
):
    get = conditional_mock_utils.mock_http_get()
    runner = CliRunner()
    result = runner.invoke(
        metadata_add,
        ["example.com", "SOA-EDIT-API", example_soa_edit_api["metadata"][0]],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "already present" in json.loads(result.output)["message"]
    get.assert_called()


def test_metadata_add_failed(mock_utils, testobject, conditional_mock_utils, example_new_data):
    get = conditional_mock_utils.mock_http_get()
    post = mock_utils.mock_http_post(500, json_output={"error": "Request failed"})
    runner = CliRunner()
    result = runner.invoke(
        metadata_add,
        ["example.com", example_new_data["kind"], example_new_data["metadata"][0]],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    assert "Failed" in json.loads(result.output)["message"]
    post.assert_called()
    get.assert_called()


def test_metadata_import_success(
    conditional_mock_utils, testobject, mock_utils, file_mock, example_new_data
):
    get = conditional_mock_utils.mock_http_get()
    post = mock_utils.mock_http_post(201, json_output={"message": "OK"})
    file_mock.mock_settings_import(copy.deepcopy([example_new_data]))
    runner = CliRunner()
    result = runner.invoke(
        metadata_import,
        ["example.com", "testfile"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "Successfully" in json.loads(result.output)["message"]
    post.assert_called()
    get.assert_called()


def test_metadata_import_idempotence(
    conditional_mock_utils, testobject, file_mock, example_also_notify
):
    get = conditional_mock_utils.mock_http_get()
    file_mock.mock_settings_import(copy.deepcopy([example_also_notify]))
    runner = CliRunner()
    result = runner.invoke(
        metadata_import,
        ["example.com", "testfile"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "already" in json.loads(result.output)["message"]
    get.assert_called()


def test_metadata_import_failed(
    mock_utils, testobject, conditional_mock_utils, file_mock, example_new_data
):
    get = conditional_mock_utils.mock_http_get()
    mock_utils.mock_http_post(500, json_output={"error": "Request failed"})
    file_mock.mock_settings_import(copy.deepcopy([example_new_data]))
    runner = CliRunner()
    result = runner.invoke(
        metadata_import,
        ["example.com", "testfile"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    assert "Failed" in json.loads(result.output)["error"]
    get.assert_called()


testcodes_to_ignore = (
    ExitCodes(http_get_code=200, http_post_code=500, http_delete_code=500),
    ExitCodes(http_get_code=200, http_post_code=201, http_delete_code=500),
    ExitCodes(http_get_code=200, http_post_code=500, http_delete_code=500),
)


@pytest.mark.parametrize("http_get_code,http_post_code,http_delete_code", testcodes_to_ignore)
def test_metadata_import_failed(
    mock_utils,
    testobject,
    http_get_code,
    http_post_code,
    http_delete_code,
    file_mock,
    example_new_data,
    example_metadata,
):
    get = mock_utils.mock_http_get(http_get_code, json_output=example_metadata)
    post = mock_utils.mock_http_post(http_post_code, json_output={"error": "Request failed"})
    file_mock.mock_settings_import(copy.deepcopy([example_new_data]))
    runner = CliRunner()
    result = runner.invoke(
        metadata_import,
        ["example.com", "testfile", "--ignore-errors"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    get.assert_called()
    post.assert_called()


import_testcases = (
    TC(
        file_contents=[{"kind": "X-NEW-DATA", "metadata": ["test123"], "type": "Metadata"}],
        upstream_content=[
            {"kind": "SOA-EDIT-API", "metadata": ["DEFAULT"], "type": "Metadata"},
            {
                "kind": "ALSO-NOTIFY",
                "metadata": ["192.0.2.1:5305", "192.0.2.2:5305"],
                "type": "Metadata",
            },
        ],
        added_content=[{"kind": "X-NEW-DATA", "metadata": ["test123"], "type": "Metadata"}],
        delete_paths=[
            "http://example.com/api/v1/servers/localhost/zones/example.com./metadata/ALSO-NOTIFY",
        ],
    ),
    TC(
        file_contents=[],
        upstream_content=[
            {"kind": "SOA-EDIT-API", "metadata": ["DEFAULT"], "type": "Metadata"},
            {
                "kind": "ALSO-NOTIFY",
                "metadata": ["192.0.2.1:5305", "192.0.2.2:5305"],
                "type": "Metadata",
            },
        ],
        added_content=[],
        delete_paths=[
            "http://example.com/api/v1/servers/localhost/zones/example.com./metadata/ALSO-NOTIFY",
        ],
    ),
    TC(
        file_contents=[{"kind": "X-NEW-DATA", "metadata": ["test123"], "type": "Metadata"}],
        upstream_content=[
            {"kind": "SOA-EDIT-API", "metadata": ["DEFAULT"], "type": "Metadata"},
            {
                "kind": "ALSO-NOTIFY",
                "metadata": ["192.0.2.1:5305", "192.0.2.2:5305"],
                "type": "Metadata",
            },
        ],
        added_content=[{"kind": "X-NEW-DATA", "metadata": ["test123"], "type": "Metadata"}],
        delete_paths=[
            "http://example.com/api/v1/servers/localhost/zones/example.com./metadata/ALSO-NOTIFY",
        ],
    ),
    TC(
        file_contents=[{"kind": "X-NEW-DATA", "metadata": ["test123"], "type": "Metadata"}],
        upstream_content=[
            {"kind": "SOA-EDIT-API", "metadata": ["DEFAULT"], "type": "Metadata"},
        ],
        added_content=[{"kind": "X-NEW-DATA", "metadata": ["test123"], "type": "Metadata"}],
        delete_paths=[],
    ),
)


@pytest.mark.parametrize(
    "file_contents,upstream_content,added_content,delete_paths", import_testcases
)
def test_metadata_import_replace_success(
    mock_utils, testobject, file_mock, file_contents, upstream_content, added_content, delete_paths
):
    get = mock_utils.mock_http_get(
        200,
        json_output=copy.deepcopy(upstream_content),
    )
    post = mock_utils.mock_http_post(201, json_output={"message": "OK"})
    delete = mock_utils.mock_http_delete(204, json_output={"message": "OK"})
    file_mock.mock_settings_import(copy.deepcopy(file_contents))
    runner = CliRunner()
    result = runner.invoke(
        metadata_import,
        ["example.com", "testfile", "--replace"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "Successfully" in json.loads(result.output)["message"]
    for content in added_content:
        assert content in [items.kwargs["payload"] for items in post.call_args_list]
    for path in delete_paths:
        assert path in [items.args[0] for items in delete.call_args_list]
    assert delete.call_count == len(delete_paths)
    assert post.call_count == len(added_content)
    get.assert_called()


def test_metadata_import_replace_idempotence(
    conditional_mock_utils, testobject, file_mock, example_metadata
):
    get = conditional_mock_utils.mock_http_get()
    file_mock.mock_settings_import(copy.deepcopy(example_metadata))
    runner = CliRunner()
    result = runner.invoke(
        metadata_import,
        ["example.com", "testfile", "--replace"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "already" in json.loads(result.output)["message"]
    get.assert_called()


testcodes = (
    ExitCodes(http_get_code=500, http_post_code=100, http_delete_code=100),
    ExitCodes(http_get_code=200, http_post_code=500, http_delete_code=100),
    ExitCodes(http_get_code=200, http_post_code=201, http_delete_code=500),
)


@pytest.mark.parametrize("http_get_code,http_delete_code,http_post_code", testcodes)
def test_metadata_import_replace_early_exit(
    mock_utils,
    testobject,
    file_mock,
    example_new_data,
    example_metadata,
    http_get_code,
    http_delete_code,
    http_post_code,
):
    get = mock_utils.mock_http_get(http_get_code, json_output=example_new_data)
    post = mock_utils.mock_http_post(http_post_code, json_output={"message": "OK"})
    delete = mock_utils.mock_http_delete(http_delete_code, json_output={"message": "OK"})
    file_mock.mock_settings_import(copy.deepcopy([example_new_data]))
    runner = CliRunner()
    result = runner.invoke(
        metadata_import,
        ["example.com", "testfile", "--replace"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    get.assert_called()
    if http_delete_code == 204:
        delete.assert_called()
    if http_delete_code == 100:
        delete.assert_not_called()
    if http_post_code == 201:
        post.assert_called()
    if http_post_code == 100:
        post.assert_not_called()


testcodes_to_ignore = (
    ExitCodes(http_get_code=200, http_post_code=500, http_delete_code=204),
    ExitCodes(http_get_code=200, http_post_code=201, http_delete_code=500),
    ExitCodes(http_get_code=200, http_post_code=500, http_delete_code=500),
)


@pytest.mark.parametrize("http_get_code,http_delete_code,http_post_code", testcodes_to_ignore)
def test_metadata_import_replace_ignore_errors(
    mock_utils,
    testobject,
    file_mock,
    example_new_data,
    example_metadata,
    http_get_code,
    http_delete_code,
    http_post_code,
):
    get = mock_utils.mock_http_get(http_get_code, json_output=example_metadata)
    post = mock_utils.mock_http_post(http_post_code, json_output={"message": "OK"})
    delete = mock_utils.mock_http_delete(http_delete_code, json_output={"message": "OK"})
    file_mock.mock_settings_import(copy.deepcopy([example_new_data]))
    runner = CliRunner()
    result = runner.invoke(
        metadata_import,
        ["example.com", "testfile", "--replace", "--ignore-errors"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    get.assert_called()
    post.assert_called()
    delete.assert_called()


def test_metadata_export_success(conditional_mock_utils, testobject, example_metadata):
    get = conditional_mock_utils.mock_http_get()
    runner = CliRunner()
    result = runner.invoke(
        metadata_export,
        ["example.com"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert json.loads(result.output)["data"] == example_metadata
    get.assert_called()


def test_metadata_extend_success(
    mock_utils, testobject, conditional_mock_utils, example_also_notify
):
    get = conditional_mock_utils.mock_http_get()
    example_also_notify["metadata"].extend("192.168.123.111")
    post = mock_utils.mock_http_post(201, json_output=example_also_notify)
    runner = CliRunner()
    result = runner.invoke(
        metadata_extend,
        ["example.com", example_also_notify["kind"], "192.168.123.111"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert json.loads(result.output)["data"] == example_also_notify
    post.assert_called()
    get.assert_called()


def test_metadata_extend_idempotence(
    mock_utils, testobject, conditional_mock_utils, example_also_notify
):
    get = conditional_mock_utils.mock_http_get()
    runner = CliRunner()
    result = runner.invoke(
        metadata_extend,
        ["example.com", example_also_notify["kind"], example_also_notify["metadata"][1]],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "already present" in json.loads(result.output)["message"]
    get.assert_called()


def test_metadata_extend_failed(
    mock_utils, testobject, conditional_mock_utils, example_also_notify
):
    get = conditional_mock_utils.mock_http_get()
    post = mock_utils.mock_http_post(500, json_output={"error": "Request failed"})
    runner = CliRunner()
    result = runner.invoke(
        metadata_extend,
        ["example.com", example_also_notify["kind"], "192.168.123.111"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    assert "Failed" in json.loads(result.output)["message"]
    post.assert_called()
    get.assert_called()


def test_metadata_update_success(
    mock_utils, testobject, conditional_mock_utils, example_also_notify
):
    get = conditional_mock_utils.mock_http_get()
    example_also_notify["metadata"] = ["192.168.123.111"]
    put = mock_utils.mock_http_put(200, json_output=example_also_notify)
    runner = CliRunner()
    result = runner.invoke(
        metadata_update,
        ["example.com", example_also_notify["kind"], "192.168.123.111"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert json.loads(result.output)["data"] == example_also_notify
    put.assert_called()
    get.assert_called()


def test_metadata_update_idempotence(
    mock_utils, testobject, conditional_mock_utils, example_soa_edit_api
):
    get = conditional_mock_utils.mock_http_get()
    runner = CliRunner()
    result = runner.invoke(
        metadata_update,
        ["example.com", example_soa_edit_api["kind"], example_soa_edit_api["metadata"][0]],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "already present" in json.loads(result.output)["message"]
    get.assert_called()


def test_metadata_update_failed(
    mock_utils, testobject, conditional_mock_utils, example_also_notify
):
    get = conditional_mock_utils.mock_http_get()
    put = mock_utils.mock_http_put(500, json_output={"error": "Not found"})
    runner = CliRunner()
    result = runner.invoke(
        metadata_update,
        ["example.com", example_also_notify["kind"], "192.168.123.111"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    assert "Failed" in json.loads(result.output)["message"]
    put.assert_called()
    get.assert_called()


def test_metadata_delete_success(
    mock_utils, testobject, conditional_mock_utils, example_also_notify
):
    get = conditional_mock_utils.mock_http_get()
    delete = mock_utils.mock_http_delete(204, json_output={"message": "Deleted"})
    runner = CliRunner()
    result = runner.invoke(
        metadata_delete,
        ["example.com", example_also_notify["kind"]],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "Deleted" in json.loads(result.output)["message"]
    delete.assert_called()
    get.assert_called()


def test_metadata_delete_idempotence(
    mock_utils, testobject, conditional_mock_utils, example_also_notify
):
    get = conditional_mock_utils.mock_http_get()
    runner = CliRunner()
    result = runner.invoke(
        metadata_delete,
        ["example.com", "X-NEW-DATA"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "already" in json.loads(result.output)["message"]
    get.assert_called()


def test_metadata_delete_failed(
    mock_utils, testobject, conditional_mock_utils, example_also_notify
):
    get = conditional_mock_utils.mock_http_get()
    delete = mock_utils.mock_http_delete(500, json_output={"Error": "failed"})
    runner = CliRunner()
    result = runner.invoke(
        metadata_delete,
        ["example.com", example_also_notify["kind"]],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    assert "Failed" in json.loads(result.output)["message"]
    delete.assert_called()
    get.assert_called()
