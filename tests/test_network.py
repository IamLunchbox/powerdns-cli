import copy
import json
from typing import NamedTuple, TypedDict

import pytest
from click.testing import CliRunner
from powerdns_cli_test_utils import testutils

from powerdns_cli.commands.network import (
    network_add,
    network_delete,
    network_export,
    network_import,
    network_list,
)


@pytest.fixture
def mock_utils(mocker):
    return testutils.MockUtils(mocker)


@pytest.fixture
def file_mock(mocker):
    return testutils.MockFile(mocker)


class AddedNetwork(TypedDict):
    uri: str
    payload: dict[str, str]


class NetworkImport(NamedTuple):
    import_file: dict[str, list[dict[str, str]]]
    upstream_network: dict[str, list[dict[str, str]]]
    added_network: list[AddedNetwork]
    deleted_path: list[str]


class NetworkImportIdempotence(NamedTuple):
    import_file: dict[str, list[dict[str, str]]]
    upstream_network: dict[str, list[dict[str, str]]]


@pytest.mark.parametrize(
    "valid_networks,statuscode,output",
    (
        ("0.0.0.0/0", 404, {"error": "Not found"}),
        ("10.0.0.0/8", 200, {"network": "10.0.0.0/8", "view": "test2"}),
        ("fe80::/128", 200, {"network": "fe80::/128", "view": "test2"}),
    ),
)
def test_network_add_success(mock_utils, valid_networks, statuscode, output):
    get = mock_utils.mock_http_get(statuscode, json_output=output)
    put = mock_utils.mock_http_put(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        network_add,
        [valid_networks, "test1"],
        obj=testutils.testobject,
    )
    assert result.exit_code == 0
    assert "Added" in json.loads(result.output)["message"]
    get.assert_called_once()
    put.assert_called_once()


@pytest.mark.parametrize(
    "valid_networks,statuscode,output",
    (
        ("0.0.0.0/0", 200, {"network": "0.0.0.0/0", "view": "test1"}),
        ("10.0.0.0/8", 200, {"network": "10.0.0.0/8", "view": "test1"}),
        ("fe80::/128", 200, {"network": "fe80::/128", "view": "test1"}),
    ),
)
def test_network_add_idempotence(mock_utils, valid_networks, statuscode, output):
    get = mock_utils.mock_http_get(statuscode, json_output=output)
    runner = CliRunner()
    result = runner.invoke(
        network_add,
        [valid_networks, "test1"],
        obj=testutils.testobject,
    )
    assert result.exit_code == 0
    assert "already" in json.loads(result.output)["message"]
    get.assert_called_once()


def test_network_add_failed(mock_utils):
    get = mock_utils.mock_http_get(200, json_output={"network": "10.0.0.8", "view": "test2"})
    put = mock_utils.mock_http_put(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        network_add,
        ["10.0.0.0/8", "test1"],
        obj=testutils.testobject,
    )
    assert result.exit_code == 1
    assert json.loads(result.output)["error"] == "Server error"
    put.assert_called_once()
    get.assert_called_once()


@pytest.mark.parametrize(
    "valid_networks,output",
    (
        ("0.0.0.0/0", {"network": "0.0.0.0/0", "view": "test2"}),
        ("10.0.0.0/8", {"network": "10.0.0.0/8", "view": "test2"}),
        ("fe80::/128", {"network": "fe80::/128", "view": "test2"}),
    ),
)
def test_network_delete_success(mock_utils, valid_networks, output):
    get = mock_utils.mock_http_get(200, json_output=output)
    put = mock_utils.mock_http_put(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        network_delete,
        [valid_networks],
        obj=testutils.testobject,
    )
    assert result.exit_code == 0
    assert "Removed" in json.loads(result.output)["message"]
    get.assert_called_once()
    put.assert_called_once()


def test_network_delete_idempotence(
    mock_utils,
):
    get = mock_utils.mock_http_get(404, json_output={"error": "Not found"})
    put = mock_utils.mock_http_put(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        network_delete,
        ["0.0.0.0/0"],
        obj=testutils.testobject,
    )
    assert result.exit_code == 0
    assert "absent" in json.loads(result.output)["message"]
    get.assert_called_once()
    put.assert_not_called()


def test_network_delete_failed(
    mock_utils,
):
    get = mock_utils.mock_http_get(200, json_output={"network": "0.0.0.0/0", "view": "test2"})
    put = mock_utils.mock_http_put(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        network_delete,
        ["0.0.0.0/0"],
        obj=testutils.testobject,
    )
    assert result.exit_code == 1
    assert json.loads(result.output)["error"] == "Server error"
    get.assert_called_once()
    put.assert_called_once()


testcases = (
    NetworkImport(
        import_file={"networks": [{"network": "0.0.0.0/0", "view": "test"}]},
        upstream_network={},
        added_network=[
            AddedNetwork(
                uri="http://example.com/api/v1/servers/localhost/networks/0.0.0.0/0",
                payload={"view": "test"},
            )
        ],
        deleted_path=[],
    ),
    NetworkImport(
        import_file={
            "networks": [
                {"network": "0.0.0.0/0", "view": "test"},
                {"network": "fe80::0/10", "view": "test"},
                {"network": "149.112.112.112/16", "view": "example"},
            ]
        },
        upstream_network={"networks": [{"network": "0.0.0.0/0", "view": "test1"}]},
        added_network=[
            AddedNetwork(
                uri="http://example.com/api/v1/servers/localhost/networks/0.0.0.0/0",
                payload={"view": "test"},
            ),
            AddedNetwork(
                uri="http://example.com/api/v1/servers/localhost/networks/fe80::0/10",
                payload={"view": "test"},
            ),
            AddedNetwork(
                uri="http://example.com/api/v1/servers/localhost/networks/149.112.112.112/16",
                payload={"view": "example"},
            ),
        ],
        deleted_path=["http://example.com/api/v1/servers/localhost/networks/0.0.0.0/0"],
    ),
)


@pytest.mark.parametrize("import_file,upstream_network,added_network,deleted_path", testcases)
def test_network_import_success(
    mock_utils, file_mock, import_file, upstream_network, added_network, deleted_path
):
    get = mock_utils.mock_http_get(200, json_output=upstream_network)
    put = mock_utils.mock_http_put(204, text_output="")
    file_mock.mock_settings_import(import_file)
    runner = CliRunner()
    result = runner.invoke(
        network_import,
        ["testfile"],
        obj=testutils.testobject,
    )
    assert result.exit_code == 0
    assert "imported" in json.loads(result.output)["message"]
    get.assert_called_once()
    put.assert_called()
    for network in added_network:
        assert network["payload"] in [item.kwargs["payload"] for item in put.call_args_list]
        assert network["uri"] in [item.args[0] for item in put.call_args_list]


testcases_idempotence = (
    NetworkImportIdempotence(
        import_file={"networks": [{"network": "0.0.0.0/0", "view": "test"}]},
        upstream_network={"networks": [{"network": "0.0.0.0/0", "view": "test"}]},
    ),
    NetworkImportIdempotence(
        import_file={"networks": [{"network": "149.112.112.112/16", "view": "example"}]},
        upstream_network={
            "networks": [
                {"network": "0.0.0.0/0", "view": "test"},
                {"network": "fe80::0/10", "view": "test"},
                {"network": "149.112.112.112/16", "view": "example"},
            ]
        },
    ),
    NetworkImportIdempotence(
        import_file={"networks": []},
        upstream_network={"networks": [{"network": "0.0.0.0/0", "view": "test"}]},
    ),
    NetworkImportIdempotence(import_file={"networks": []}, upstream_network={"networks": []}),
)


@pytest.mark.parametrize("import_file,upstream_network", testcases_idempotence)
def test_network_import_idempotence(mock_utils, file_mock, import_file, upstream_network):
    get = mock_utils.mock_http_get(200, json_output=upstream_network)
    file_mock.mock_settings_import(import_file)
    runner = CliRunner()
    result = runner.invoke(
        network_import,
        ["testfile"],
        obj=testutils.testobject,
    )
    assert result.exit_code == 0
    assert "already" in json.loads(result.output)["message"]
    get.assert_called_once()


@pytest.mark.parametrize("import_file,upstream_network,added_network,deleted_path", testcases)
def test_network_import_failed(
    mock_utils, file_mock, import_file, upstream_network, added_network, deleted_path
):
    get = mock_utils.mock_http_get(200, json_output=upstream_network)
    put = mock_utils.mock_http_put(500, json_output={"error": "Server error"})
    file_mock.mock_settings_import(import_file)
    runner = CliRunner()
    result = runner.invoke(
        network_import,
        ["testfile"],
        obj=testutils.testobject,
    )
    assert result.exit_code == 1
    get.assert_called_once()
    put.assert_called()


@pytest.mark.parametrize("import_file,upstream_network,added_network,deleted_path", testcases)
def test_network_import_early_exit(
    mock_utils, file_mock, import_file, upstream_network, added_network, deleted_path
):
    get = mock_utils.mock_http_get(200, json_output=upstream_network)
    put = mock_utils.mock_http_put(500, json_output={"error": "Server error"})
    file_mock.mock_settings_import(import_file)
    runner = CliRunner()
    result = runner.invoke(
        network_import,
        ["testfile"],
        obj=testutils.testobject,
    )
    assert result.exit_code == 1
    get.assert_called_once()
    put.assert_called_once()


def test_network_import_ignore_errors(mock_utils, file_mock):
    get = mock_utils.mock_http_get(
        200,
        json_output={"networks": []},
    )
    put = mock_utils.mock_http_put(500, text_output="")
    file_mock.mock_settings_import(
        {
            "networks": [
                {"network": "0.0.0.0/0", "view": "test"},
                {"network": "fe80::/10", "view": "test1"},
            ]
        }
    )
    runner = CliRunner()
    result = runner.invoke(
        network_import,
        ["testfile", "--ignore-errors"],
        obj=testutils.testobject,
    )
    assert result.exit_code == 0
    assert "imported" in json.loads(result.stdout)["message"]
    assert len(result.stderr) > 0
    assert put.call_count == 2
    get.assert_called_once()


testcases_replace = (
    NetworkImport(
        import_file={"networks": []},
        upstream_network={"networks": [{"network": "0.0.0.0/0", "view": "test"}]},
        added_network=[],
        deleted_path=["http://example.com/api/v1/servers/localhost/networks/0.0.0.0/0"],
    ),
) + testcases


@pytest.mark.parametrize(
    "import_file,upstream_network,added_network,deleted_path", testcases_replace
)
def test_network_import_replace_success(
    mock_utils, file_mock, import_file, upstream_network, added_network, deleted_path
):
    get = mock_utils.mock_http_get(200, json_output=upstream_network)
    put = mock_utils.mock_http_put(204, text_output="")
    file_mock.mock_settings_import(import_file)
    runner = CliRunner()
    result = runner.invoke(
        network_import,
        ["testfile", "--replace"],
        obj=testutils.testobject,
    )
    assert result.exit_code == 0
    assert "imported" in json.loads(result.output)["message"]
    get.assert_called_once()
    assert put.call_count == len(added_network) + len(deleted_path)
    for network in added_network:
        assert network["payload"] in [item.kwargs["payload"] for item in put.call_args_list]
        assert network["uri"] in [item.args[0] for item in put.call_args_list]

    for path in deleted_path:
        assert path in [item.args[0] for item in put.call_args_list]


testcases_idempotence_replace = (
    NetworkImportIdempotence(
        import_file={"networks": [{"network": "0.0.0.0/0", "view": "test"}]},
        upstream_network={"networks": [{"network": "0.0.0.0/0", "view": "test"}]},
    ),
    NetworkImportIdempotence(
        import_file={"networks": []},
        upstream_network={"networks": []},
    ),
)


@pytest.mark.parametrize("import_file,upstream_network", testcases_idempotence_replace)
def test_network_import_replace_idempotence(mock_utils, file_mock, import_file, upstream_network):
    get = mock_utils.mock_http_get(200, json_output=upstream_network)
    file_mock.mock_settings_import(import_file)
    runner = CliRunner()
    result = runner.invoke(
        network_import,
        ["testfile", "--replace"],
        obj=testutils.testobject,
    )
    assert result.exit_code == 0
    assert "already" in json.loads(result.output)["message"]
    get.assert_called_once()


def test_network_import_replace_failed(mock_utils, file_mock):
    get = mock_utils.mock_http_get(
        200,
        json_output={
            "networks": [
                {"network": "0.0.0.0/0", "view": "test"},
                {"network": "fe80::/10", "view": "test1"},
            ]
        },
    )
    put = mock_utils.mock_http_put(500, json_output={"error": "Server error"})
    file_mock.mock_settings_import({"networks": []})
    runner = CliRunner()
    result = runner.invoke(
        network_import,
        ["testfile", "--replace"],
        obj=testutils.testobject,
    )
    assert result.exit_code == 1
    get.assert_called_once()
    put.assert_called()


def test_network_import_replace_early_exit(
    mock_utils,
    file_mock,
):
    get = mock_utils.mock_http_get(
        200,
        json_output={
            "networks": [
                {"network": "0.0.0.0/0", "view": "test"},
                {"network": "fe80::/10", "view": "test1"},
            ]
        },
    )
    put = mock_utils.mock_http_put(500, json_output={"error": "Server error"})
    file_mock.mock_settings_import({"networks": []})
    runner = CliRunner()
    result = runner.invoke(
        network_import,
        ["testfile", "--replace"],
        obj=testutils.testobject,
    )
    assert result.exit_code == 1
    get.assert_called_once()
    put.assert_called_once()


def test_network_import_replace_ignore_errors(mock_utils, file_mock):
    get = mock_utils.mock_http_get(
        200,
        json_output={
            "networks": [
                {"network": "0.0.0.0/0", "view": "test"},
                {"network": "fe80::/10", "view": "test1"},
            ]
        },
    )
    put = mock_utils.mock_http_put(500, text_output="")
    file_mock.mock_settings_import({"networks": []})
    runner = CliRunner()
    result = runner.invoke(
        network_import,
        ["testfile", "--replace", "--ignore-errors"],
        obj=testutils.testobject,
    )
    assert result.exit_code == 0
    assert "imported" in json.loads(result.stdout)["message"]
    assert len(result.stderr) > 0
    get.assert_called_once()
    assert put.call_count == 2


def test_network_list_success(
    mock_utils,
):
    list_output = [
        {"network": "0.0.0.0/0", "view": "test2"},
        {"network": "0.0.0.0/1", "view": "test1"},
    ]
    get = mock_utils.mock_http_get(200, json_output=copy.deepcopy(list_output))
    runner = CliRunner()
    result = runner.invoke(
        network_list,
        [],
        obj=testutils.testobject,
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == list_output
    get.assert_called_once()


def test_network_list_failed(
    mock_utils,
):
    get = mock_utils.mock_http_get(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        network_list,
        [],
        obj=testutils.testobject,
    )
    assert result.exit_code == 1
    assert json.loads(result.output)["error"] == "Server error"
    get.assert_called_once()


def test_network_export_success(
    mock_utils,
):
    network_output = {"network": "0.0.0.0/0", "view": "test2"}
    get = mock_utils.mock_http_get(200, json_output=copy.deepcopy(network_output))
    runner = CliRunner()
    result = runner.invoke(
        network_export,
        ["0.0.0.0/0"],
        obj=testutils.testobject,
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == network_output
    get.assert_called_once()


def test_network_export_failed(
    mock_utils,
):
    get = mock_utils.mock_http_get(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        network_export,
        ["0.0.0.0/0"],
        obj=testutils.testobject,
    )
    assert result.exit_code == 1
    assert json.loads(result.output)["error"] == "Server error"
    get.assert_called_once()
