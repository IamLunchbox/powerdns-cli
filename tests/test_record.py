import copy
import json

import pytest
from click.testing import CliRunner
from powerdns_cli_test_utils import testutils

from powerdns_cli.powerdns_cli import (
    record_add,
    record_delete,
    record_disable,
    record_enable,
    record_export,
    record_extend,
)

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
def mock_utils(mocker):
    return testutils.MockUtils(mocker)


@pytest.fixture
def example_zone():
    return copy.deepcopy(example_zone_dict)


def test_record_add_success(mock_utils, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_add,
        ["@", "example.com.", "A", "192.168.1.1"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert "created" in json.loads(result.output)["message"]
    patch.assert_called()
    get.assert_called_once()


def test_record_add_already_present(mock_utils, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_add,
        ["test", "example.com.", "A", "1.1.1.1"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    patch.assert_not_called()
    get.assert_called_once()
    assert "already present" in json.loads(result.output)["message"]


def test_record_add_failure(mock_utils, example_zone):
    get = mock_utils.mock_http_get(404, {"error": "Not found"})
    patch = mock_utils.mock_http_patch(500, {"error": "Internal server error"})
    runner = CliRunner()
    result = runner.invoke(
        record_add,
        ["@", "example.com.", "A", "192.168.1.1"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 1
    patch.assert_not_called()


def test_record_delete_success(mock_utils, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_delete,
        ["test", "example.com.", "A", "1.1.1.1"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert "removed" in json.loads(result.output)["message"]
    get.assert_called()
    patch.assert_called()


def test_record_delete_already_absent(mock_utils, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_delete,
        ["test", "example.com.", "A", "192.168.1.1"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert "already absent" in json.loads(result.output)["message"]
    patch.assert_not_called()


def test_record_delete_failure(mock_utils, example_zone):
    get = mock_utils.mock_http_get(404, {"error": "Not found"})
    patch = mock_utils.mock_http_patch(500, {"error": "Internal server error"})
    runner = CliRunner()
    result = runner.invoke(
        record_delete,
        ["@", "example.com.", "A", "192.168.1.1"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 1
    patch.assert_not_called()


def test_record_disable_success(mock_utils, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_disable,
        ["test", "example.com.", "A", "1.1.1.1", "--ttl", "3600"],
        obj={"apihost": "http://example.com"},
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


def test_record_disable_already_disabled(mock_utils, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_disable,
        ["test", "example.com.", "A", "1.1.1.2"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    patch.assert_not_called()
    get.assert_called_once()
    assert "already disabled" in json.loads(result.output)["message"]


def test_record_disable_failure(mock_utils, example_zone):
    get = mock_utils.mock_http_get(404, {"error": "Not found"})
    patch = mock_utils.mock_http_patch(500, {"error": "Internal server error"})
    runner = CliRunner()
    result = runner.invoke(
        record_disable,
        ["@", "example.com.", "A", "192.168.1.1"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 1
    patch.assert_not_called()


def test_record_enable_success(mock_utils, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_enable,
        ["test", "example.com.", "A", "1.1.1.2"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert "created" in json.loads(result.output)["message"]
    patch.assert_called()
    get.assert_called()


def test_record_already_enabled(mock_utils, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_enable,
        ["test", "example.com.", "A", "1.1.1.1"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert "already present" in json.loads(result.output)["message"]
    patch.assert_not_called()
    get.assert_called()


def test_record_enabled_failure(mock_utils, example_zone):
    get = mock_utils.mock_http_get(404, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_enable,
        ["test", "example.com.", "A", "1.1.1.1"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 1
    patch.assert_not_called()
    get.assert_called()


def test_record_extend_success(mock_utils, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_extend,
        ["test", "example.com.", "A", "192.168.1.1"],
        obj={"apihost": "http://example.com"},
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


def test_record_extend_success_with_new_rrset(mock_utils, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_extend,
        ["test4", "example.com.", "A", "192.168.1.1"],
        obj={"apihost": "http://example.com"},
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


def test_record_extend_idempotence(mock_utils, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_extend,
        ["test", "example.com.", "A", "1.1.1.1"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert "already present" in json.loads(result.output)["message"]
    patch.assert_not_called()
    get.assert_called()


def test_record_extend_failure(mock_utils, example_zone):
    get = mock_utils.mock_http_get(404, {"error": "Not found"})
    patch = mock_utils.mock_http_patch(500, {"error": "Internal server error"})
    runner = CliRunner()
    result = runner.invoke(
        record_extend,
        ["@", "example.com.", "A", "192.168.1.1"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 1
    patch.assert_not_called()


def test_record_extend_success_with_new_rrset(mock_utils, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    patch = mock_utils.mock_http_patch(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        record_extend,
        ["test4", "example.com.", "A", "192.168.1.1"],
        obj={"apihost": "http://example.com"},
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


def test_record_export_success(mock_utils, example_zone):
    get = mock_utils.mock_http_get(200, example_zone)
    runner = CliRunner()
    result = runner.invoke(
        record_export,
        ["example.com.","--name", "test2", "--type", "A"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == [
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
        }
    ]
    get.assert_called()


def test_record_export_failure(mock_utils, example_zone):
    get = mock_utils.mock_http_get(404, {"error": "Not found"})
    runner = CliRunner()
    result = runner.invoke(
        record_export,
        ["example.com."],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 1
    assert json.loads(result.output) == {"error": "Not found"}
    get.assert_called()
