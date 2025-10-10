import copy
import json
from typing import NamedTuple

import pytest
from click.testing import CliRunner
from powerdns_cli_test_utils import testutils
from powerdns_cli_test_utils.testutils import mock_utils, testenvironment, testobject

from powerdns_cli.commands.view import (
    view_add,
    view_delete,
    view_export,
    view_import,
    view_list,
    view_update,
)


@pytest.fixture
def file_mock(mocker):
    return testutils.MockFile(mocker)


class ViewImports(NamedTuple):
    file_contents: list[dict[str, list[str]]]
    upstream_views: list[dict[str, list[str]]]
    added_views: list[dict]
    delete_path: list[str]


@pytest.mark.parametrize(
    "returncodes,return_content",
    (
        (200, {"zones": ["example.com..variant1"]}),
        (404, {"error": "Not found"}),
    ),
)
def test_view_add_success(mock_utils, testobject, returncodes, return_content):
    get = mock_utils.mock_http_get(returncodes, json_output=return_content)
    post = mock_utils.mock_http_post(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        view_add,
        ["test1", "example.com..variant2"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "Added" in json.loads(result.output)["message"]
    get.assert_called_once()
    post.assert_called_once()


def test_view_add_idempotence(mock_utils, testobject):
    get = mock_utils.mock_http_get(
        200, json_output={"zones": ["example.com..variant1", "example.com."]}
    )
    post = mock_utils.mock_http_post(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        view_add,
        ["test1", "example.com"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "already" in json.loads(result.output)["message"]
    get.assert_called_once()
    post.assert_not_called()


def test_view_add_failed(mock_utils, testobject):
    get = mock_utils.mock_http_get(
        200, json_output={"zones": ["example.com..variant1", "example.com."]}
    )
    post = mock_utils.mock_http_post(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        view_add,
        ["test1", "example.com..variant3"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    assert "Failed" in json.loads(result.output)["message"]
    get.assert_called_once()
    post.assert_called_once()


testcases = (
    ViewImports(
        file_contents=[{"test1": ["example.org"]}, {"test2": ["example.com", "test.info"]}],
        upstream_views=[],
        added_views=[
            {
                "path": "http://example.com/api/v1/servers/localhost/views/test1",
                "name": "example.org.",
            },
            {
                "path": "http://example.com/api/v1/servers/localhost/views/test2",
                "name": "example.com.",
            },
            {
                "path": "http://example.com/api/v1/servers/localhost/views/test2",
                "name": "example.org.",
            },
        ],
        delete_path=[],
    ),
    ViewImports(
        file_contents=[{"test1": ["example.org"]}, {"test2": ["example.com", "test.info"]}],
        upstream_views=[{"name": "test1", "views": {"example.org"}}],
        added_views=[
            {
                "path": "http://example.com/api/v1/servers/localhost/views/test1",
                "name": "example.org.",
            },
            {
                "path": "http://example.com/api/v1/servers/localhost/views/test2",
                "name": "example.com.",
            },
            {
                "path": "http://example.com/api/v1/servers/localhost/views/test2",
                "name": "test.info.",
            },
        ],
        delete_path=[],
    ),
)


@pytest.mark.parametrize("file_contents,upstream_views,added_views,delete_path", testcases)
def test_view_import_success(
    mocker,
    mock_utils,
    testobject,
    file_mock,
    file_contents,
    upstream_views,
    added_views,
    delete_path,
):
    mocker.patch("powerdns_cli.commands.view.get_upstream_views", return_value=upstream_views)
    file_mock.mock_settings_import(file_contents)
    post = mock_utils.mock_http_post(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        view_import,
        ["testfile"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "Successfully" in json.loads(result.output)["message"]
    assert post.call_count == len(added_views)
    for item in added_views:
        assert item["path"] in [call.args[0] for call in post.call_args_list]
        assert item["name"] in [call.kwargs["payload"]["name"] for call in post.call_args_list]


testcases_idempotence = (
    ViewImports(
        file_contents=[{"test1": ["example.org."]}, {"test2": ["example.com.", "test.info."]}],
        upstream_views=[
            {"name": "test1", "views": {"example.org."}},
            {"name": "test2", "views": {"example.com.", "test.info."}},
        ],
        added_views=[],
        delete_path=[],
    ),
    ViewImports(
        file_contents=[{"test2": ["example.com."]}],
        upstream_views=[
            {"name": "test1", "views": {"example.org."}},
            {"name": "test2", "views": {"example.com.", "test.info."}},
        ],
        added_views=[],
        delete_path=[],
    ),
    ViewImports(
        file_contents=[],
        upstream_views=[{"name": "test1", "views": {"example.org"}}],
        added_views=[],
        delete_path=[],
    ),
)


@pytest.mark.parametrize(
    "file_contents,upstream_views,added_views,delete_path", testcases_idempotence
)
def test_view_import_idempotence(
    mocker,
    mock_utils,
    testobject,
    file_mock,
    file_contents,
    upstream_views,
    added_views,
    delete_path,
):
    mocker.patch("powerdns_cli.commands.view.get_upstream_views", return_value=upstream_views)
    file_mock.mock_settings_import(file_contents)
    runner = CliRunner()
    result = runner.invoke(
        view_import,
        ["testfile"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "already" in json.loads(result.output)["message"]


def test_view_import_failed(
    mocker,
    mock_utils,
    testobject,
    file_mock,
):
    mocker.patch(
        "powerdns_cli.commands.view.get_upstream_views",
        return_value=[{"name": "test1", "views": {"example.org"}}],
    )
    file_mock.mock_settings_import(
        [{"test1": ["example.org"]}, {"test2": ["example.com", "test.info"]}]
    )
    post = mock_utils.mock_http_post(500, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        view_import,
        ["testfile"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    assert "Failed" in json.loads(result.output)["message"]
    post.assert_called_once()


def test_view_import_early_exit(
    mocker,
    mock_utils,
    testobject,
    file_mock,
):
    mocker.patch("powerdns_cli.commands.view.get_upstream_views", return_value=[])
    file_mock.mock_settings_import(
        [{"test1": ["example.org"]}, {"test2": ["example.com", "test.info"]}]
    )
    post = mock_utils.mock_http_post(500, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        view_import,
        ["testfile"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    assert "Failed" in json.loads(result.output)["message"]
    post.assert_called_once()


def test_view_import_ignore_errors(
    mocker,
    mock_utils,
    testobject,
    file_mock,
):
    mocker.patch("powerdns_cli.commands.view.get_upstream_views", return_value=[])
    file_mock.mock_settings_import(
        [{"test1": ["example.org"]}, {"test2": ["example.com", "test.info"]}]
    )
    post = mock_utils.mock_http_post(500, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        view_import,
        ["testfile", "--ignore-errors"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "Successfully" in json.loads(result.stdout)["message"]
    assert len(post.call_args_list) == 3


testcases_replace = (
    ViewImports(
        file_contents=[{"test1": ["example.org"]}, {"test2": ["example.com", "test.info"]}],
        upstream_views=[],
        added_views=[
            {
                "path": "http://example.com/api/v1/servers/localhost/views/test1",
                "name": "example.org.",
            },
            {
                "path": "http://example.com/api/v1/servers/localhost/views/test2",
                "name": "example.com.",
            },
            {
                "path": "http://example.com/api/v1/servers/localhost/views/test2",
                "name": "example.org.",
            },
        ],
        delete_path=[],
    ),
    ViewImports(
        file_contents=[{"test1": ["example.org"]}, {"test2": ["example.com", "test.info."]}],
        upstream_views=[
            {"name": "test", "views": {"example.com."}},
            {"name": "test2", "views": {"test.info.", "anothertest.info."}},
        ],
        added_views=[
            {
                "path": "http://example.com/api/v1/servers/localhost/views/test1",
                "name": "example.org.",
            },
            {
                "path": "http://example.com/api/v1/servers/localhost/views/test2",
                "name": "example.com.",
            },
        ],
        delete_path=[
            "http://example.com/api/v1/servers/localhost/views/test/example.com.",
            "http://example.com/api/v1/servers/localhost/views/test2/anothertest.info.",
        ],
    ),
    ViewImports(
        file_contents=[],
        upstream_views=[
            {"name": "test", "views": {"example.com."}},
            {"name": "test2", "views": {"anothertest.info."}},
        ],
        added_views=[],
        delete_path=[
            "http://example.com/api/v1/servers/localhost/views/test/example.com.",
            "http://example.com/api/v1/servers/localhost/views/test2/anothertest.info.",
        ],
    ),
)


@pytest.mark.parametrize("file_contents,upstream_views,added_views,delete_path", testcases_replace)
def test_view_import_replace_success(
    mocker,
    mock_utils,
    testobject,
    file_mock,
    file_contents,
    upstream_views,
    added_views,
    delete_path,
):
    mocker.patch("powerdns_cli.commands.view.get_upstream_views", return_value=upstream_views)
    file_mock.mock_settings_import(file_contents)
    post = mock_utils.mock_http_post(204, text_output="")
    delete = mock_utils.mock_http_delete(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        view_import,
        ["testfile", "--replace"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "Successfully" in json.loads(result.output)["message"]
    assert post.call_count == len(added_views)
    assert delete.call_count == len(delete_path)

    for item in added_views:
        assert item["path"] in [call.args[0] for call in post.call_args_list]
        assert item["name"] in [call.kwargs["payload"]["name"] for call in post.call_args_list]
    for item in delete_path:
        assert item in [call.args[0] for call in delete.call_args_list]


testcases_replace_idempotence = (
    ViewImports(
        file_contents=[{"test1": ["example.org"]}, {"test2": ["test.info.", "example.org."]}],
        upstream_views=[
            {"name": "test1", "views": {"example.org."}},
            {"name": "test2", "views": {"test.info.", "example.org."}},
        ],
        added_views=[],
        delete_path=[],
    ),
    ViewImports(
        file_contents=[],
        upstream_views=[],
        added_views=[],
        delete_path=[],
    ),
)


@pytest.mark.parametrize(
    "file_contents,upstream_views,added_views,delete_path", testcases_replace_idempotence
)
def test_view_import_replace_idempotence(
    mocker,
    mock_utils,
    testobject,
    file_mock,
    file_contents,
    upstream_views,
    added_views,
    delete_path,
):
    mocker.patch("powerdns_cli.commands.view.get_upstream_views", return_value=upstream_views)
    file_mock.mock_settings_import(file_contents)
    post = mock_utils.mock_http_post(204, text_output="")
    delete = mock_utils.mock_http_delete(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        view_import,
        ["testfile", "--replace"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "already" in json.loads(result.output)["message"]
    assert post.call_count == len(added_views)
    assert delete.call_count == len(delete_path)


@pytest.mark.parametrize(
    "post_code,delete_code,post_calls,delete_calls",
    (
        (500, 100, 1, 0),
        (204, 500, 3, 1),
    ),
)
def test_view_import_replace_early_exit(
    mocker, mock_utils, testobject, file_mock, post_code, delete_code, post_calls, delete_calls
):
    mocker.patch(
        "powerdns_cli.commands.view.get_upstream_views",
        return_value=[
            {"name": "test", "views": {"example.com."}},
            {"name": "test2", "views": {"test.info.", "anothertest.info."}},
        ],
    )
    file_mock.mock_settings_import(
        [{"test1": ["example.org", "example.com"]}, {"test2": ["example.com", "test.info."]}]
    )
    post = mock_utils.mock_http_post(post_code, text_output="")
    delete = mock_utils.mock_http_delete(delete_code, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        view_import,
        ["testfile", "--replace"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    assert "Failed" in json.loads(result.stdout)["message"]
    assert post.call_count == post_calls
    assert delete.call_count == delete_calls


def test_view_import_replace_ignore_errors(
    mocker,
    mock_utils,
    testobject,
    file_mock,
):
    mocker.patch(
        "powerdns_cli.commands.view.get_upstream_views",
        return_value=[
            {"name": "test", "views": {"example.com."}},
            {"name": "test2", "views": {"test.info.", "anothertest.info."}},
        ],
    )
    file_mock.mock_settings_import(
        [{"test1": ["example.org", "example.com"]}, {"test2": ["example.com", "test.info."]}]
    )
    post = mock_utils.mock_http_post(500, text_output="")
    delete = mock_utils.mock_http_delete(500, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        view_import,
        ["testfile", "--replace", "--ignore-errors"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "Successfully" in json.loads(result.stdout)["message"]
    assert post.call_count == 3
    assert delete.call_count == 2


@pytest.mark.parametrize(
    "returncodes,return_content",
    (
        (200, {"zones": ["example.com..variant1"]}),
        (404, {"error": "Not found"}),
    ),
)
def test_view_update_success(mock_utils, testobject, returncodes, return_content):
    get = mock_utils.mock_http_get(returncodes, json_output=return_content)
    post = mock_utils.mock_http_post(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        view_update,
        ["test1", "example.com..variant2"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "Added" in json.loads(result.output)["message"]
    get.assert_called_once()
    post.assert_called_once()


def test_view_update_idempotence(mock_utils, testobject):
    get = mock_utils.mock_http_get(
        200, json_output={"zones": ["example.com..variant1", "example.com."]}
    )
    post = mock_utils.mock_http_post(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        view_update,
        ["test1", "example.com"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "already" in json.loads(result.output)["message"]
    get.assert_called_once()
    post.assert_not_called()


def test_view_update_failed(mock_utils, testobject):
    get = mock_utils.mock_http_get(
        200, json_output={"zones": ["example.com..variant1", "example.com."]}
    )
    post = mock_utils.mock_http_post(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        view_update,
        ["test1", "example.com..variant3"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    assert "Failed" in json.loads(result.output)["message"]
    get.assert_called_once()
    post.assert_called_once()


def test_view_delete_success(mock_utils, testobject):
    get = mock_utils.mock_http_get(
        200, json_output={"zones": ["example.com..variant1", "example.com."]}
    )
    delete = mock_utils.mock_http_delete(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        view_delete,
        ["test1", "example.com..variant1"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "Deleted" in json.loads(result.output)["message"]
    get.assert_called_once()
    delete.assert_called_once()


@pytest.mark.parametrize(
    "returncodes,return_content,response_keyword",
    (
        (200, {"zones": ["example.com..variant1"]}, "is not in"),
        (404, {"error": "Not found"}, "absent"),
    ),
)
def test_view_delete_idempotence(
    mock_utils, testobject, returncodes, return_content, response_keyword
):
    get = mock_utils.mock_http_get(returncodes, json_output=return_content)
    delete = mock_utils.mock_http_delete(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        view_delete,
        ["test1", "example.com..variant2"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert response_keyword in json.loads(result.output)["message"]
    get.assert_called_once()
    delete.assert_not_called()


def test_view_delete_failed(mock_utils, testobject):
    get = mock_utils.mock_http_get(
        200, json_output={"zones": ["example.com..variant1", "example.com."]}
    )
    delete = mock_utils.mock_http_delete(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        view_delete,
        ["test1", "example.com..variant1"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    assert "Failed" in json.loads(result.output)["message"]
    get.assert_called_once()
    delete.assert_called_once()


def test_view_list_success(mock_utils, testobject):
    output_list = {"views": ["test1", "test2"]}
    get = mock_utils.mock_http_get(200, json_output=copy.deepcopy(output_list))
    runner = CliRunner()
    result = runner.invoke(
        view_list,
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert json.loads(result.output)["data"] == output_list
    get.assert_called_once()


def test_view_list_failed(mock_utils, testobject):
    get = mock_utils.mock_http_get(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        view_list,
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    assert "Failed" in json.loads(result.output)["message"]
    get.assert_called_once()


def test_view_export_success(mock_utils, testobject):
    output_dict = {"zones": ["example.com..variant1"]}
    get = mock_utils.mock_http_get(200, json_output=copy.deepcopy(output_dict))
    runner = CliRunner()
    result = runner.invoke(
        view_export,
        ["test1"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert json.loads(result.output)["data"] == output_dict
    get.assert_called_once()


def test_view_export_failed(mock_utils, testobject):
    get = mock_utils.mock_http_get(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        view_export,
        ["test1"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    assert "Failed" in json.loads(result.output)["message"]
    get.assert_called_once()
