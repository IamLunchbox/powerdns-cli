import copy
import json

import pytest
from click.testing import CliRunner
from powerdns_cli_test_utils import testutils

from powerdns_cli.powerdns_cli import (
    view_add,
    view_delete,
    view_export,
    view_list,
    view_update,
)


@pytest.fixture
def mock_utils(mocker):
    return testutils.MockUtils(mocker)


@pytest.mark.parametrize(
    "returncodes,return_content",
    (
        (200, {"zones": ["example.com..variant1"]}),
        (404, {"error": "Not found"}),
    ),
)
def test_view_add_success(mock_utils, returncodes, return_content):
    get = mock_utils.mock_http_get(returncodes, json_output=return_content)
    post = mock_utils.mock_http_post(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        view_add,
        ["test1", "example.com..variant2"],
        obj={"apihost": "http://example.com", "major_version": 5},
    )
    assert result.exit_code == 0
    assert "Added" in json.loads(result.output)["message"]
    get.assert_called_once()
    post.assert_called_once()


def test_view_add_idempotence(mock_utils):
    get = mock_utils.mock_http_get(
        200, json_output={"zones": ["example.com..variant1", "example.com."]}
    )
    post = mock_utils.mock_http_post(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        view_add,
        ["test1", "example.com"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert "already" in json.loads(result.output)["message"]
    get.assert_called_once()
    post.assert_not_called()


def test_view_add_failed(mock_utils):
    get = mock_utils.mock_http_get(
        200, json_output={"zones": ["example.com..variant1", "example.com."]}
    )
    post = mock_utils.mock_http_post(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        view_add,
        ["test1", "example.com..variant3"],
        obj={"apihost": "http://example.com", "major_version": 5},
    )
    assert result.exit_code == 1
    assert json.loads(result.output)["error"] == "Server error"
    get.assert_called_once()
    post.assert_called_once()


@pytest.mark.parametrize(
    "returncodes,return_content",
    (
        (200, {"zones": ["example.com..variant1"]}),
        (404, {"error": "Not found"}),
    ),
)
def test_view_update_success(mock_utils, returncodes, return_content):
    get = mock_utils.mock_http_get(returncodes, json_output=return_content)
    post = mock_utils.mock_http_post(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        view_update,
        ["test1", "example.com..variant2"],
        obj={"apihost": "http://example.com", "major_version": 5},
    )
    assert result.exit_code == 0
    assert "Added" in json.loads(result.output)["message"]
    get.assert_called_once()
    post.assert_called_once()


def test_view_update_idempotence(mock_utils):
    get = mock_utils.mock_http_get(
        200, json_output={"zones": ["example.com..variant1", "example.com."]}
    )
    post = mock_utils.mock_http_post(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        view_update,
        ["test1", "example.com"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert "already" in json.loads(result.output)["message"]
    get.assert_called_once()
    post.assert_not_called()


def test_view_update_failed(mock_utils):
    get = mock_utils.mock_http_get(
        200, json_output={"zones": ["example.com..variant1", "example.com."]}
    )
    post = mock_utils.mock_http_post(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        view_update,
        ["test1", "example.com..variant3"],
        obj={"apihost": "http://example.com", "major_version": 5},
    )
    assert result.exit_code == 1
    assert json.loads(result.output)["error"] == "Server error"
    get.assert_called_once()
    post.assert_called_once()


def test_view_delete_success(mock_utils):
    get = mock_utils.mock_http_get(
        200, json_output={"zones": ["example.com..variant1", "example.com."]}
    )
    delete = mock_utils.mock_http_delete(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        view_delete,
        ["test1", "example.com..variant1"],
        obj={"apihost": "http://example.com", "major_version": 5},
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
def test_view_delete_idempotence(mock_utils, returncodes, return_content, response_keyword):
    get = mock_utils.mock_http_get(returncodes, json_output=return_content)
    delete = mock_utils.mock_http_delete(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        view_delete,
        ["test1", "example.com..variant2"],
        obj={"apihost": "http://example.com", "major_version": 5},
    )
    assert result.exit_code == 0
    assert response_keyword in json.loads(result.output)["message"]
    get.assert_called_once()
    delete.assert_not_called()


def test_view_delete_failed(mock_utils):
    get = mock_utils.mock_http_get(
        200, json_output={"zones": ["example.com..variant1", "example.com."]}
    )
    delete = mock_utils.mock_http_delete(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        view_delete,
        ["test1", "example.com..variant1"],
        obj={"apihost": "http://example.com", "major_version": 5},
    )
    assert result.exit_code == 1
    assert json.loads(result.output)["error"] == "Server error"
    get.assert_called_once()
    delete.assert_called_once()


def test_view_list_success(mock_utils):
    output_list = {"views": ["test1", "test2"]}
    get = mock_utils.mock_http_get(200, json_output=copy.deepcopy(output_list))
    runner = CliRunner()
    result = runner.invoke(
        view_list,
        obj={"apihost": "http://example.com", "major_version": 5},
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == output_list
    get.assert_called_once()


def test_view_list_failed(mock_utils):
    get = mock_utils.mock_http_get(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        view_list,
        obj={"apihost": "http://example.com", "major_version": 5},
    )
    assert result.exit_code == 1
    assert json.loads(result.output)["error"] == "Server error"
    get.assert_called_once()


def test_view_export_success(mock_utils):
    output_dict = {"zones": ["example.com..variant1"]}
    get = mock_utils.mock_http_get(200, json_output=copy.deepcopy(output_dict))
    runner = CliRunner()
    result = runner.invoke(
        view_export,
        ["test1"],
        obj={"apihost": "http://example.com", "major_version": 5},
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == output_dict
    get.assert_called_once()


def test_view_export_failed(mock_utils):
    get = mock_utils.mock_http_get(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        view_export,
        ["test1"],
        obj={"apihost": "http://example.com", "major_version": 5},
    )
    assert result.exit_code == 1
    assert json.loads(result.output)["error"] == "Server error"
    get.assert_called_once()
