import copy
import json
from typing import NamedTuple

import pytest
from click.testing import CliRunner
from powerdns_cli_test_utils import testutils
from powerdns_cli_test_utils.testutils import mock_utils, testenvironment, testobject

from powerdns_cli.commands.autoprimary import (
    autoprimary_add,
    autoprimary_delete,
    autoprimary_import,
    autoprimary_list,
)


@pytest.fixture
def file_mock(mocker):
    return testutils.MockFile(mocker)


def test_autoprimary_add_success(mock_utils, testobject):
    get = mock_utils.mock_http_get(200, [{"ip": "2.2.2.2", "nameserver": "ns1.example.com"}])
    post = mock_utils.mock_http_post(201, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        autoprimary_add,
        ["1.1.1.1", "ns1.example.com", "--account", "testaccount"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "added" in json.loads(result.output)["message"]
    get.assert_called()
    post.assert_called()


def test_autoprimary_add_idempotence(mock_utils, testobject):
    get = mock_utils.mock_http_get(
        200,
        json_output=[{"ip": "1.1.1.1", "nameserver": "ns1.example.com", "account": "testaccount"}],
    )
    post = mock_utils.mock_http_post(201, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        autoprimary_add,
        ["1.1.1.1", "ns1.example.com"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "present" in json.loads(result.output)["message"]
    get.assert_called()
    post.assert_not_called()


def test_autoprimary_list_success(mock_utils, testobject):
    get = mock_utils.mock_http_get(200, [{"ip": "2.2.2.2", "nameserver": "ns1.example.com"}])
    runner = CliRunner()
    result = runner.invoke(
        autoprimary_list,
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert json.loads(result.output)["data"] == [{"ip": "2.2.2.2", "nameserver": "ns1.example.com"}]
    get.assert_called()


def test_autoprimary_delete_success(mock_utils, testobject):
    get = mock_utils.mock_http_get(
        200, [{"ip": "2.2.2.2", "nameserver": "ns1.example.com", "account": "testaccount"}]
    )
    delete = mock_utils.mock_http_delete(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        autoprimary_delete,
        ["2.2.2.2", "ns1.example.com"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "deleted" in json.loads(result.output)["message"]
    get.assert_called()
    delete.assert_called()


def test_autoprimary_delete_already_absent(mock_utils, testobject):
    get = mock_utils.mock_http_get(
        200, [{"ip": "2.2.2.2", "nameserver": "ns1.example.com", "account": "testaccount"}]
    )
    delete = mock_utils.mock_http_delete(201, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        autoprimary_delete,
        ["1.1.1.1", "ns1.example.com"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "already absent" in json.loads(result.output)["message"]
    get.assert_called()
    delete.assert_not_called()


@pytest.mark.parametrize(
    "file_contents",
    (
        [
            {"ip": "1.1.1.1", "nameserver": "ns.example.com"},
            {"ip": "1.1.1.2", "nameserver": "ns3.example.com"},
        ],
        [
            {"ip": "1.1.1.1", "nameserver": "ns.example.com", "account": "testaccount"},
        ],
        [{"ip": "2.2.2.2", "nameserver": "ns1.example.com"}],
    ),
)
def test_autoprimary_import_success(mock_utils, file_mock, file_contents, testobject):
    get = mock_utils.mock_http_get(
        200,
        copy.deepcopy(
            [{"ip": "2.2.2.2", "nameserver": "ns1.example.com", "account": "testaccount"}]
        ),
    )
    post = mock_utils.mock_http_post(201, {"success": True})
    file_mock.mock_settings_import(copy.deepcopy(file_contents))
    runner = CliRunner()
    result = runner.invoke(
        autoprimary_import,
        ["testfile"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "autoprimary" in json.loads(result.output)["message"]
    get.assert_called()
    post.assert_called()
    for item in file_contents:
        assert item in [post_request[2]["payload"] for post_request in post.mock_calls]


@pytest.mark.parametrize(
    "file_contents",
    (
        [{"ip": "2.2.2.2", "nameserver": "ns1.example.com", "account": "testaccount"}],
        [
            {"ip": "2.2.2.2", "nameserver": "ns1.example.com", "account": "testaccount"},
            {"ip": "1.1.1.1", "nameserver": "ns.example.com"},
        ],
    ),
)
def test_autoprimary_import_idempotence(mock_utils, file_mock, file_contents, testobject):
    get = mock_utils.mock_http_get(
        200,
        copy.deepcopy(
            [
                {"ip": "2.2.2.2", "nameserver": "ns1.example.com", "account": "testaccount"},
                {"ip": "1.1.1.1", "nameserver": "ns.example.com"},
            ]
        ),
    )
    post = mock_utils.mock_http_post(201, {"success": True})
    file_mock.mock_settings_import(copy.deepcopy(file_contents))
    runner = CliRunner()
    result = runner.invoke(
        autoprimary_import,
        ["testfile"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "already present" in json.loads(result.output)["message"]
    get.assert_called()
    post.assert_not_called()


class TC(NamedTuple):
    upstream_content: list[dict[str, str]]
    file_contents: list[dict[str, str]]
    added_content: list[dict[str, str]]
    delete_paths: list[str]


import_testcases = (
    TC(
        upstream_content=[
            {"ip": "2.2.2.2", "nameserver": "ns1.example.com", "account": "testaccount"},
            {"ip": "3.3.3.3", "nameserver": "ns2.example.com"},
        ],
        file_contents=[
            {"ip": "1.1.1.1", "nameserver": "ns.example.com"},
            {"ip": "1.1.1.2", "nameserver": "ns3.example.com"},
        ],
        added_content=[
            {"ip": "1.1.1.1", "nameserver": "ns.example.com"},
            {"ip": "1.1.1.2", "nameserver": "ns3.example.com"},
        ],
        delete_paths=[
            "http://example.com/api/v1/servers/localhost/autoprimaries/ns1.example.com/2.2.2.2",
            "http://example.com/api/v1/servers/localhost/autoprimaries/ns2.example.com/3.3.3.3",
        ],
    ),
    TC(
        upstream_content=[],
        file_contents=[
            {"ip": "1.1.1.1", "nameserver": "ns.example.com", "account": "testaccount"},
        ],
        added_content=[
            {"ip": "1.1.1.1", "nameserver": "ns.example.com", "account": "testaccount"},
        ],
        delete_paths=[],
    ),
    TC(
        upstream_content=[
            {"ip": "2.2.2.2", "nameserver": "ns1.example.com", "account": "testaccount"},
            {"ip": "3.3.3.3", "nameserver": "ns2.example.com"},
        ],
        file_contents=[{"ip": "2.2.2.2", "nameserver": "ns1.example.com"}],
        added_content=[],
        delete_paths=[
            "http://example.com/api/v1/servers/localhost/autoprimaries/ns2.example.com/3.3.3.3"
        ],
    ),
    TC(
        upstream_content=[
            {"ip": "3.3.3.3", "nameserver": "ns2.example.com"},
        ],
        file_contents=[],
        added_content=[],
        delete_paths=[
            "http://example.com/api/v1/servers/localhost/autoprimaries/ns2.example.com/3.3.3.3"
        ],
    ),
)


@pytest.mark.parametrize(
    "upstream_content,file_contents,added_content,delete_paths", import_testcases
)
def test_autoprimary_import_replace_success(
    mock_utils, file_mock, upstream_content, file_contents, added_content, delete_paths, testobject
):
    get = mock_utils.mock_http_get(
        200,
        copy.deepcopy(upstream_content),
    )
    post = mock_utils.mock_http_post(201, {"success": True})
    delete = mock_utils.mock_http_delete(204, {"success": True})
    file_mock.mock_settings_import(copy.deepcopy(file_contents))
    runner = CliRunner()
    result = runner.invoke(
        autoprimary_import,
        ["testfile", "--replace"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "autoprimary" in json.loads(result.output)["message"]
    get.assert_called()
    if added_content:
        post.assert_called()
    if delete_paths:
        delete.assert_called()
    for item in added_content:
        assert item in [post_request[2]["payload"] for post_request in post.mock_calls]
    for item in delete_paths:
        assert item in [delete_request[1][0] for delete_request in delete.mock_calls]


def test_autoprimary_import_replace_idempotence(mock_utils, file_mock, testobject):
    get = mock_utils.mock_http_get(
        200,
        copy.deepcopy(
            [
                {"ip": "2.2.2.2", "nameserver": "ns1.example.com", "account": "testaccount"},
                {"ip": "1.1.1.1", "nameserver": "ns.example.com"},
            ]
        ),
    )
    file_contents = [
        {"ip": "2.2.2.2", "nameserver": "ns1.example.com", "account": "testaccount"},
        {"ip": "1.1.1.1", "nameserver": "ns.example.com"},
    ]
    post = mock_utils.mock_http_post(201, {"success": True})
    delete = mock_utils.mock_http_delete(204, {"success": True})
    file_mock.mock_settings_import(copy.deepcopy(file_contents))
    runner = CliRunner()
    result = runner.invoke(
        autoprimary_import,
        ["testfile", "--replace"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "already present" in json.loads(result.output)["message"]
    get.assert_called()
    post.assert_not_called()
    delete.assert_not_called()


class ErrorCodes(NamedTuple):
    get_status: int
    post_status: int
    delete_status: int


returncodes = (
    ErrorCodes(
        get_status=200,
        post_status=500,
        delete_status=204,
    ),
    ErrorCodes(
        get_status=200,
        post_status=201,
        delete_status=500,
    ),
)


@pytest.mark.parametrize("get_status,post_status,delete_status", returncodes)
def test_autoprimary_import_replace_error(
    mock_utils, file_mock, get_status, post_status, delete_status, testobject
):
    get = mock_utils.mock_http_get(
        get_status,
        copy.deepcopy(
            [
                {"ip": "2.2.2.2", "nameserver": "ns1.example.com", "account": "testaccount"},
                {"ip": "1.1.1.1", "nameserver": "ns.example.com"},
            ]
        ),
    )
    file_contents = [
        {"ip": "3.3.2.2", "nameserver": "ns1.example.com", "account": "testaccount"},
        {"ip": "1.1.2.2", "nameserver": "ns.example.com"},
    ]
    mock_utils.mock_http_post(post_status, {"success": True})
    delete = mock_utils.mock_http_delete(delete_status, {"success": True})
    file_mock.mock_settings_import(copy.deepcopy(file_contents))
    runner = CliRunner()
    result = runner.invoke(
        autoprimary_import,
        ["testfile", "--replace"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    get.assert_called()
    if post_status == 500:
        delete.assert_not_called()

    if get_status == 500:
        delete.assert_called()


@pytest.mark.parametrize("get_status,post_status,delete_status", returncodes)
def test_autoprimary_import_ignore_error(
    mock_utils, file_mock, get_status, post_status, delete_status, testobject
):
    get = mock_utils.mock_http_get(
        get_status,
        copy.deepcopy(
            [
                {"ip": "2.2.2.2", "nameserver": "ns1.example.com", "account": "testaccount"},
                {"ip": "1.1.1.1", "nameserver": "ns.example.com"},
            ]
        ),
    )
    file_contents = [
        {"ip": "3.3.2.2", "nameserver": "ns1.example.com", "account": "testaccount"},
        {"ip": "1.1.2.2", "nameserver": "ns.example.com"},
    ]
    post = mock_utils.mock_http_post(post_status, {"success": True})
    delete = mock_utils.mock_http_delete(delete_status, {"success": True})
    file_mock.mock_settings_import(copy.deepcopy(file_contents))
    runner = CliRunner()
    result = runner.invoke(
        autoprimary_import,
        ["testfile", "--replace", "--ignore-errors"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    get.assert_called()
    assert delete.call_count == 2
    assert post.call_count == 2
