import copy
import json
from typing import Any, NamedTuple
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner
from powerdns_cli_test_utils import testutils
from powerdns_cli_test_utils.testutils import mock_utils, testenvironment, testobject

from powerdns_cli.commands.record import (
    record_add,
    record_delete,
    record_disable,
    record_enable,
    record_export,
    record_extend,
    record_import,
)

example_com_bind = """example.com.    3600    IN      SOA     a.misconfigured.dns.server.invalid. hostmaster.example.com. 2025082405 10800 3600 604800 3600
mail.example.com.       86400   IN      MX      0 mail.example.com.
test.example.com.       86400   IN      A       10.0.0.1
test.example.com.       86400   IN      A       10.0.0.2
test2.example.com.      86400   IN      A       10.0.1.1
"""

example_zone_dict = {
    "account": "",
    "api_rectify": False,
    "catalog": "",
    "dnssec": False,
    "edited_serial": 2025080203,
    "id": "example.com.",
    "kind": "Master",
    "last_check": 0,
    "master_tsig_key_ids": [],
    "masters": [],
    "name": "example.com.",
    "notified_serial": 0,
    "nsec3narrow": False,
    "nsec3param": "",
    "rrsets": [
        {
            "comments": [],
            "name": "test.example.com.",
            "records": [
                {"content": "1.1.1.1", "disabled": False},
                {"content": "1.1.1.2", "disabled": True},
            ],
            "ttl": 86400,
            "type": "A",
        },
        {
            "comments": [],
            "name": "test2.example.com.",
            "records": [{"content": "2.2.2.2", "disabled": True}],
            "ttl": 86400,
            "type": "A",
        },
        {
            "comments": [],
            "name": "example.com.",
            "records": [
                {
                    "content": "a.misconfigured.dns.server.invalid. hostmaster.example.com. 2025080203 10800 3600 604800 3600",
                    "disabled": False,
                }
            ],
            "ttl": 3600,
            "type": "SOA",
        },
    ],
    "serial": 2025080203,
    "slave_tsig_key_ids": [],
    "soa_edit": "",
    "soa_edit_api": "DEFAULT",
    "url": "/api/v1/servers/localhost/zones/example.com.",
}


@pytest.fixture
def example_zone():
    return copy.deepcopy(example_zone_dict)


@pytest.fixture
def file_mock(mocker):
    return testutils.MockFile(mocker)


def test_record_add_success(mock_utils, testobject, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_add,
        ["@", "example.com.", "A", "192.168.1.1"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "created" in json.loads(result.output)["message"]
    patch.assert_called()
    get.assert_called_once()


def test_record_add_already_present(mock_utils, testobject, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_add,
        ["test", "example.com.", "A", "1.1.1.1"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    patch.assert_not_called()
    get.assert_called_once()
    assert "already present" in json.loads(result.output)["message"]


def test_record_add_failure(mock_utils, testobject, example_zone):
    mock_utils.mock_http_get(404, {"error": "Not found"})
    patch = mock_utils.mock_http_patch(500, {"error": "Internal server error"})
    runner = CliRunner()
    result = runner.invoke(
        record_add,
        ["@", "example.com.", "A", "192.168.1.1"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    patch.assert_not_called()


def test_record_delete_success(mock_utils, testobject, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_delete,
        ["test", "example.com.", "A", "1.1.1.1"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "removed" in json.loads(result.output)["message"]
    get.assert_called()
    patch.assert_called()


def test_record_delete_already_absent(mock_utils, testobject, example_zone):
    mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_delete,
        ["test", "example.com.", "A", "192.168.1.1"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "already absent" in json.loads(result.output)["message"]
    patch.assert_not_called()


def test_record_delete_failure(mock_utils, testobject, example_zone):
    mock_utils.mock_http_get(404, {"error": "Not found"})
    patch = mock_utils.mock_http_patch(500, {"error": "Internal server error"})
    runner = CliRunner()
    result = runner.invoke(
        record_delete,
        ["@", "example.com.", "A", "192.168.1.1"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    patch.assert_not_called()


def test_record_disable_success(mock_utils, testobject, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_disable,
        ["test", "example.com.", "A", "1.1.1.1", "--ttl", "3600"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "disabled" in json.loads(result.output)["message"]
    patch.assert_called()
    assert patch.call_args_list[0][0][2] == {
        "rrsets": [
            {
                "name": "test.example.com.",
                "type": "A",
                "ttl": 3600,
                "changetype": "REPLACE",
                "records": [
                    {"content": "1.1.1.1", "disabled": True},
                    {"content": "1.1.1.2", "disabled": True},
                ],
            }
        ]
    }
    get.assert_called()


def test_record_disable_already_disabled(mock_utils, testobject, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_disable,
        ["test", "example.com.", "A", "1.1.1.2"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    patch.assert_not_called()
    get.assert_called_once()
    assert "already disabled" in json.loads(result.output)["message"]


def test_record_disable_failure(mock_utils, testobject, example_zone):
    mock_utils.mock_http_get(404, {"error": "Not found"})
    patch = mock_utils.mock_http_patch(500, {"error": "Internal server error"})
    runner = CliRunner()
    result = runner.invoke(
        record_disable,
        ["@", "example.com.", "A", "192.168.1.1"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    patch.assert_not_called()


def test_record_enable_success(mock_utils, testobject, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_enable,
        ["test", "example.com.", "A", "1.1.1.2"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "created" in json.loads(result.output)["message"]
    patch.assert_called()
    get.assert_called()


def test_record_already_enabled(mock_utils, testobject, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_enable,
        ["test", "example.com.", "A", "1.1.1.1"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "already present" in json.loads(result.output)["message"]
    patch.assert_not_called()
    get.assert_called()


def test_record_enabled_failure(mock_utils, testobject, example_zone):
    get = mock_utils.mock_http_get(404, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_enable,
        ["test", "example.com.", "A", "1.1.1.1"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    patch.assert_not_called()
    get.assert_called()


def test_record_extend_success(mock_utils, testobject, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_extend,
        ["test", "example.com.", "A", "192.168.1.1"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "extended" in json.loads(result.output)["message"]
    patch.assert_called()
    assert patch.call_args_list[0][0][2] == {
        "rrsets": [
            {
                "name": "test.example.com.",
                "type": "A",
                "ttl": 86400,
                "changetype": "REPLACE",
                "records": [
                    {"content": "192.168.1.1", "disabled": False},
                    {"content": "1.1.1.1", "disabled": False},
                    {"content": "1.1.1.2", "disabled": True},
                ],
            }
        ]
    }
    get.assert_called()


def test_record_extend_success_with_new_rrset(mock_utils, testobject, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_extend,
        ["test4", "example.com.", "A", "192.168.1.1"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "extended" in json.loads(result.output)["message"]
    patch.assert_called()
    assert patch.call_args_list[0][0][2] == {
        "rrsets": [
            {
                "name": "test4.example.com.",
                "type": "A",
                "ttl": 86400,
                "changetype": "REPLACE",
                "records": [
                    {"content": "192.168.1.1", "disabled": False},
                ],
            }
        ]
    }
    get.assert_called()


def test_record_extend_idempotence(mock_utils, testobject, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_extend,
        ["test", "example.com.", "A", "1.1.1.1"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "already present" in json.loads(result.output)["message"]
    patch.assert_not_called()
    get.assert_called()


def test_record_extend_failure(mock_utils, testobject, example_zone):
    mock_utils.mock_http_get(404, {"error": "Not found"})
    patch = mock_utils.mock_http_patch(500, {"error": "Internal server error"})
    runner = CliRunner()
    result = runner.invoke(
        record_extend,
        ["@", "example.com.", "A", "192.168.1.1"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    patch.assert_not_called()


def test_record_export_success(mock_utils, testobject, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    runner = CliRunner()
    result = runner.invoke(
        record_export,
        ["example.com.", "--name", "test2", "--type", "A"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert json.loads(result.output)["data"]["rrsets"] == [
        {
            "comments": [],
            "name": "test.example.com.",
            "records": [
                {"content": "1.1.1.1", "disabled": False},
                {"content": "1.1.1.2", "disabled": True},
            ],
            "ttl": 86400,
            "type": "A",
        },
        {
            "comments": [],
            "name": "test2.example.com.",
            "records": [{"content": "2.2.2.2", "disabled": True}],
            "ttl": 86400,
            "type": "A",
        },
    ]
    get.assert_called()


def test_record_export_failure(mock_utils, testobject, example_zone):
    get = mock_utils.mock_http_get(404, {"error": "Not found"})
    runner = CliRunner()
    result = runner.invoke(
        record_export,
        ["example.com."],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    assert "Failed" in json.loads(result.output)["message"]
    get.assert_called()


class RRsetImport(NamedTuple):
    file_content: dict[str, Any]
    upstream_content: dict[str, Any]
    added_content: dict
    deleted_content: list[str]


testcase = (
    RRsetImport(
        file_content={
            "id": "example.com.",
            "rrsets": [
                {
                    "comments": [],
                    "name": "test.example.com.",
                    "records": [
                        {"content": "10.0.0.1", "disabled": False},
                        {"content": "10.0.0.2", "disabled": False},
                    ],
                    "ttl": 86400,
                    "type": "A",
                },
                {
                    "comments": [],
                    "name": "mail.example.com.",
                    "records": [{"content": "0 mail.example.com.", "disabled": False}],
                    "ttl": 86400,
                    "type": "MX",
                },
            ],
        },
        upstream_content={"rrsets": []},
        added_content={
            "id": "example.com.",
            "rrsets": [
                {
                    "changetype": "REPLACE",
                    "comments": [],
                    "name": "test.example.com.",
                    "records": [
                        {"content": "10.0.0.1", "disabled": False},
                        {"content": "10.0.0.2", "disabled": False},
                    ],
                    "ttl": 86400,
                    "type": "A",
                },
                {
                    "changetype": "REPLACE",
                    "comments": [],
                    "name": "mail.example.com.",
                    "records": [{"content": "0 mail.example.com.", "disabled": False}],
                    "ttl": 86400,
                    "type": "MX",
                },
            ],
        },
        deleted_content=[],
    ),
    RRsetImport(
        file_content={
            "name": "example.com.",
            "rrsets": [
                {
                    "comments": [],
                    "name": "test.example.com.",
                    "records": [
                        {"content": "10.0.0.1", "disabled": False},
                        {"content": "10.0.0.2", "disabled": False},
                    ],
                    "ttl": 86400,
                    "type": "A",
                },
                {
                    "comments": [],
                    "name": "test2.example.com.",
                    "records": [
                        {"content": "10.0.0.3", "disabled": True},
                    ],
                    "ttl": 86400,
                    "type": "A",
                },
            ],
        },
        upstream_content={
            "rrsets": [
                {
                    "comments": [],
                    "name": "test.example.com.",
                    "records": [
                        {"content": "10.0.0.3", "disabled": False},
                        {"content": "10.0.0.4", "disabled": False},
                    ],
                    "ttl": 86400,
                    "type": "A",
                },
                {
                    "comments": [],
                    "name": "mail.example.com.",
                    "records": [{"content": "0 mail.example.com.", "disabled": False}],
                    "ttl": 86400,
                    "type": "MX",
                },
                {
                    "comments": [],
                    "name": "test2.example.com.",
                    "records": [
                        {"content": "10.0.0.3", "disabled": True},
                    ],
                    "ttl": 86400,
                    "type": "A",
                },
            ],
        },
        added_content={
            "id": "example.com.",
            "rrsets": [
                {
                    "changetype": "REPLACE",
                    "comments": [],
                    "name": "test.example.com.",
                    "records": [
                        {"content": "10.0.0.1", "disabled": False},
                        {"content": "10.0.0.2", "disabled": False},
                    ],
                    "ttl": 86400,
                    "type": "A",
                },
                {
                    "changetype": "REPLACE",
                    "comments": [],
                    "name": "test2.example.com.",
                    "records": [
                        {"content": "10.0.0.3", "disabled": True},
                    ],
                    "ttl": 86400,
                    "type": "A",
                },
            ],
        },
        deleted_content=[],
    ),
)


@pytest.mark.parametrize("file_content,upstream_content,added_content,deleted_content", testcase)
def test_record_import_success(
    mock_utils,
    testobject,
    file_mock,
    file_content,
    upstream_content,
    added_content,
    deleted_content,
):
    get = mock_utils.mock_http_get(200, upstream_content)
    patch = mock_utils.mock_http_patch(204, text_output="")
    file_mock.mock_settings_import(file_content)
    runner = CliRunner()
    result = runner.invoke(
        record_import,
        ["testfile"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "imported" in json.loads(result.output)["message"]
    patch.assert_called()
    get.assert_called_once()
    assert added_content == patch.call_args_list[0].kwargs["payload"]


def test_record_import_failed(
    mock_utils,
    testobject,
    file_mock,
    example_zone,
):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(500, json_output={"error": "Server error"})
    file_mock.mock_settings_import(
        {
            "id": "example.com.",
            "rrsets": [
                {
                    "comments": [],
                    "name": "test.example.com.",
                    "records": [
                        {"content": "10.0.0.1", "disabled": False},
                        {"content": "10.0.0.2", "disabled": False},
                    ],
                    "ttl": 86400,
                    "type": "A",
                },
                {
                    "comments": [],
                    "name": "test2.example.com.",
                    "records": [
                        {"content": "10.0.0.3", "disabled": True},
                    ],
                    "ttl": 86400,
                    "type": "A",
                },
            ],
        }
    )
    runner = CliRunner()
    result = runner.invoke(
        record_import,
        ["testfile"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    assert "Failed" in json.loads(result.output)["message"]
    patch.assert_called()
    get.assert_called_once()


def test_record_import_idempotence(
    mock_utils,
    testobject,
    file_mock,
    example_zone,
):
    get = mock_utils.mock_http_get(200, example_zone)
    file_mock.mock_settings_import(
        {
            "id": "example.com.",
            "rrsets": [
                {
                    "comments": [],
                    "name": "test.example.com.",
                    "records": [
                        {"content": "1.1.1.1", "disabled": False},
                        {"content": "1.1.1.2", "disabled": True},
                    ],
                    "ttl": 86400,
                    "type": "A",
                },
                {
                    "comments": [],
                    "name": "test2.example.com.",
                    "records": [{"content": "2.2.2.2", "disabled": True}],
                    "ttl": 86400,
                    "type": "A",
                },
                {
                    "comments": [],
                    "name": "example.com.",
                    "records": [
                        {
                            "content": "a.misconfigured.dns.server.invalid. hostmaster.example.com. 2025080203 10800 3600 604800 3600",
                            "disabled": False,
                        }
                    ],
                    "ttl": 3600,
                    "type": "SOA",
                },
            ],
        }
    )
    runner = CliRunner()
    result = runner.invoke(
        record_import,
        ["testfile"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "already" in json.loads(result.output)["message"]
    get.assert_called_once()


def test_record_import_replace_success(
    mock_utils,
    testobject,
    file_mock,
    example_zone,
):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    file_mock.mock_settings_import(
        {
            "id": "example.com.",
            "rrsets": [
                {
                    "comments": [],
                    "name": "test.example.com.",
                    "records": [
                        {"content": "10.0.0.1", "disabled": False},
                        {"content": "10.0.0.2", "disabled": False},
                    ],
                    "ttl": 86400,
                    "type": "A",
                },
                {
                    "comments": [],
                    "name": "test2.example.com.",
                    "records": [
                        {"content": "10.0.0.3", "disabled": True},
                    ],
                    "ttl": 86400,
                    "type": "A",
                },
            ],
        }
    )
    added_content = [
        {
            "changetype": "REPLACE",
            "comments": [],
            "name": "test.example.com.",
            "records": [
                {"content": "10.0.0.1", "disabled": False},
                {"content": "10.0.0.2", "disabled": False},
            ],
            "ttl": 86400,
            "type": "A",
        },
        {
            "changetype": "REPLACE",
            "comments": [],
            "name": "test2.example.com.",
            "records": [
                {"content": "10.0.0.3", "disabled": True},
            ],
            "ttl": 86400,
            "type": "A",
        },
    ]
    removed_content = [
        {
            "name": "example.com.",
            "type": "SOA",
            "changetype": "DELETE",
        },
    ]
    runner = CliRunner()
    result = runner.invoke(
        record_import,
        ["testfile", "--replace"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "imported" in json.loads(result.output)["message"]
    patch.assert_called()
    get.assert_called_once()
    for item in added_content:
        assert item in patch.call_args_list[0].kwargs["payload"]["rrsets"]
    for item in removed_content:
        assert item in patch.call_args_list[0].kwargs["payload"]["rrsets"]


def test_record_import_replace_failed(
    mock_utils,
    testobject,
    file_mock,
    example_zone,
):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(500, json_output={"error": "Server error"})
    file_mock.mock_settings_import(
        {
            "id": "example.com.",
            "rrsets": [
                {
                    "comments": [],
                    "name": "test.example.com.",
                    "records": [
                        {"content": "10.0.0.1", "disabled": False},
                        {"content": "10.0.0.2", "disabled": False},
                    ],
                    "ttl": 86400,
                    "type": "A",
                },
                {
                    "comments": [],
                    "name": "test2.example.com.",
                    "records": [
                        {"content": "10.0.0.3", "disabled": True},
                    ],
                    "ttl": 86400,
                    "type": "A",
                },
            ],
        }
    )
    runner = CliRunner()
    result = runner.invoke(
        record_import,
        ["testfile", "--replace"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 1
    assert "Failed" in json.loads(result.output)["message"]
    patch.assert_called()
    get.assert_called_once()


def test_record_import_replace_idempotence(
    mock_utils,
    testobject,
    file_mock,
    example_zone,
):
    get = mock_utils.mock_http_get(200, example_zone)
    file_mock.mock_settings_import(
        {
            "id": "example.com.",
            "rrsets": [
                {
                    "comments": [],
                    "name": "test.example.com.",
                    "records": [
                        {"content": "1.1.1.1", "disabled": False},
                        {"content": "1.1.1.2", "disabled": True},
                    ],
                    "ttl": 86400,
                    "type": "A",
                },
                {
                    "comments": [],
                    "name": "test2.example.com.",
                    "records": [{"content": "2.2.2.2", "disabled": True}],
                    "ttl": 86400,
                    "type": "A",
                },
                {
                    "comments": [],
                    "name": "example.com.",
                    "records": [
                        {
                            "content": "a.misconfigured.dns.server.invalid. hostmaster.example.com. 2025080203 10800 3600 604800 3600",
                            "disabled": False,
                        }
                    ],
                    "ttl": 3600,
                    "type": "SOA",
                },
            ],
        }
    )
    runner = CliRunner()
    result = runner.invoke(
        record_import,
        ["testfile", "--replace"],
        obj=testobject,
        env=testenvironment,
    )
    assert result.exit_code == 0
    assert "already" in json.loads(result.output)["message"]
    get.assert_called_once()


def test_record_export_bind(mocker, testobject):
    def return_json():
        return {}

    response = MagicMock()
    response.text = copy.deepcopy(example_com_bind)
    response.json = return_json
    response.status_code = 200
    mocker.patch("powerdns_cli.utils.main.http_get", return_value=response)
    runner = CliRunner()
    result = runner.invoke(
        record_export, ["example.com", "-b"], obj=testobject, env=testutils.testenvironment
    )
    assert result.exit_code == 0
    assert json.loads(result.output)["message"].rstrip() == example_com_bind.rstrip()
