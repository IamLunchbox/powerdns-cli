import copy
import json

import pytest
from click.testing import CliRunner
from powerdns_cli_test_utils import testutils

from powerdns_cli.powerdns_cli import (
    network_add,
    network_delete,
    network_export,
    network_list,
)


@pytest.fixture
def mock_utils(mocker):
    return testutils.MockUtils(mocker)

@pytest.mark.parametrize("valid_networks,statuscode,output",
                         (
                                 ("0.0.0.0/0", 404, {"error": "Not found"}),
                                 ("10.0.0.0/8", 200, {"network": "10.0.0.0/8", "view": "test2"}),
                                 ("fe80::/128", 200, {"network": "fe80::/128", "view": "test2"})
                         )
                         )
def test_network_add_success(mock_utils, valid_networks, statuscode, output):
    get = mock_utils.mock_http_get(statuscode, json_output=output)
    put = mock_utils.mock_http_put(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        network_add,
        [valid_networks, "test1"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert "Added" in json.loads(result.output)["message"]
    get.assert_called_once()
    put.assert_called_once()

@pytest.mark.parametrize("valid_networks,statuscode,output",
                         (
                                 ("0.0.0.0/0", 200, {"network": "0.0.0.0/0", "view": "test1"}),
                                 ("10.0.0.0/8", 200, {"network": "10.0.0.0/8", "view": "test1"}),
                                 ("fe80::/128", 200, {"network": "fe80::/128", "view": "test1"})
                         )
                         )
def test_network_add_idempotence(mock_utils,valid_networks, statuscode, output):
    get = mock_utils.mock_http_get(statuscode, json_output=output)
    put = mock_utils.mock_http_put(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        network_add,
        [valid_networks, "test1"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert "already" in json.loads(result.output)["message"]
    get.assert_called_once()
    put.assert_not_called()

def test_network_add_failed(mock_utils):
    get = mock_utils.mock_http_get(200, json_output={"network":"10.0.0.8","view":"test2"})
    put = mock_utils.mock_http_put(500, json_output={"error":"Server error"})
    runner = CliRunner()
    result = runner.invoke(
        network_add,
        ["10.0.0.0/8", "test1"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 1
    assert json.loads(result.output)["error"] == "Server error"
    put.assert_called_once()
    get.assert_called_once()


@pytest.mark.parametrize("valid_networks,output",
                         (
                                 ("0.0.0.0/0", {"network": "0.0.0.0/0", "view": "test2"}),
                                 ("10.0.0.0/8", {"network": "10.0.0.0/8", "view": "test2"}),
                                 ("fe80::/128", {"network": "fe80::/128", "view": "test2"})
                         )
                         )
def test_network_delete_success(mock_utils, valid_networks, output):
    get = mock_utils.mock_http_get(200, json_output=output)
    put = mock_utils.mock_http_put(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        network_delete,
        [valid_networks],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert "Removed" in json.loads(result.output)["message"]
    get.assert_called_once()
    put.assert_called_once()


def test_network_delete_idempotence(mock_utils,):
    get = mock_utils.mock_http_get(404, json_output= {"error": "Not found"})
    put = mock_utils.mock_http_put(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        network_delete,
        ["0.0.0.0/0"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert "absent" in json.loads(result.output)["message"]
    get.assert_called_once()
    put.assert_not_called()

def test_network_delete_failed(mock_utils,):
    get = mock_utils.mock_http_get(200, json_output={"network": "0.0.0.0/0", "view": "test2"})
    put = mock_utils.mock_http_put(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        network_delete,
        ["0.0.0.0/0"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 1
    assert json.loads(result.output)["error"] == "Server error"
    get.assert_called_once()
    put.assert_called_once()

def test_network_list_success(mock_utils,):
    list_output = [
        {"network": "0.0.0.0/0", "view": "test2"},
        {"network": "0.0.0.0/1", "view": "test1"}
    ]
    get = mock_utils.mock_http_get(200, json_output=copy.deepcopy(list_output))
    runner = CliRunner()
    result = runner.invoke(
        network_list,
        [],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == list_output
    get.assert_called_once()

def test_network_list_failed(mock_utils,):
    get = mock_utils.mock_http_get(500, json_output={"error":"Server error"})
    runner = CliRunner()
    result = runner.invoke(
        network_list,
        [],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 1
    assert json.loads(result.output)["error"] == "Server error"
    get.assert_called_once()

def test_network_export_success(mock_utils,):
    network_output = {"network": "0.0.0.0/0", "view": "test2"}
    get = mock_utils.mock_http_get(200, json_output=copy.deepcopy(network_output))
    runner = CliRunner()
    result = runner.invoke(
        network_export,
        ["0.0.0.0/0"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == network_output
    get.assert_called_once()

def test_network_export_failed(mock_utils,):
    get = mock_utils.mock_http_get(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        network_export,
        ["0.0.0.0/0"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 1
    assert json.loads(result.output)["error"] == "Server error"
    get.assert_called_once()
