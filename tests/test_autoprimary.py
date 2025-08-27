import json

import pytest
from click.testing import CliRunner
from powerdns_cli_test_utils import testutils

from powerdns_cli.powerdns_cli import (
    autoprimary_add,
    autoprimary_delete,
    autoprimary_list,
)


@pytest.fixture
def mock_utils(mocker):
    return testutils.MockUtils(mocker)


def test_autoprimary_add_success(mock_utils):
    get = mock_utils.mock_http_get(200, [{"ip": "2.2.2.2", "nameserver": "ns1.example.com"}])
    post = mock_utils.mock_http_post(201, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        autoprimary_add,
        ["1.1.1.1", "ns1.example.com", "--account", "testaccount"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert "added" in json.loads(result.output)["message"]
    get.assert_called()
    post.assert_called()


def test_autoprimary_add_idempotence(mock_utils):
    get = mock_utils.mock_http_get(
        200, json_output=[{"ip": "1.1.1.1", "nameserver": "ns1.example.com", "account": "testaccount"}]
    )
    post = mock_utils.mock_http_post(201, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        autoprimary_add, ["1.1.1.1", "ns1.example.com"], obj={"apihost": "http://example.com"}
    )
    assert result.exit_code == 0
    assert "present" in json.loads(result.output)["message"]
    get.assert_called()
    post.assert_not_called()


def test_autoprimary_list_success(mock_utils):
    get = mock_utils.mock_http_get(200, [{"ip": "2.2.2.2", "nameserver": "ns1.example.com"}])
    runner = CliRunner()
    result = runner.invoke(autoprimary_list, obj={"apihost": "http://example.com"})
    assert result.exit_code == 0
    assert json.loads(result.output) == [{"ip": "2.2.2.2", "nameserver": "ns1.example.com"}]
    get.assert_called()


def test_autoprimary_delete_success(mock_utils):
    get = mock_utils.mock_http_get(
        200, [{"ip": "2.2.2.2", "nameserver": "ns1.example.com", "account": "testaccount"}]
    )
    delete = mock_utils.mock_http_delete(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        autoprimary_delete, ["2.2.2.2", "ns1.example.com"], obj={"apihost": "http://example.com"}
    )
    assert result.exit_code == 0
    assert "deleted" in json.loads(result.output)["message"]
    get.assert_called()
    delete.assert_called()


def test_autoprimary_delete_already_absent(mock_utils):
    get = mock_utils.mock_http_get(
        200, [{"ip": "2.2.2.2", "nameserver": "ns1.example.com", "account": "testaccount"}]
    )
    delete = mock_utils.mock_http_delete(201, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        autoprimary_delete, ["1.1.1.1", "ns1.example.com"], obj={"apihost": "http://example.com"}
    )
    assert result.exit_code == 0
    assert "already absent" in json.loads(result.output)["message"]
    get.assert_called()
    delete.assert_not_called()
