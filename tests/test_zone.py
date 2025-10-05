import copy
import json
from unittest.mock import MagicMock as unittest_MagicMock

import pytest
import requests
from click.testing import CliRunner
from powerdns_cli_test_utils import testutils

from powerdns_cli.powerdns_cli import (
    zone_add,
    zone_delete,
    zone_export,
    zone_flush_cache,
    zone_import,
    zone_list,
    zone_notify,
    zone_rectify,
    zone_search,
)

example_com_zone_dict = {
    "account": "",
    "api_rectify": False,
    "catalog": "",
    "dnssec": False,
    "edited_serial": 2025082405,
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
        {
            "comments": [],
            "name": "test2.example.com.",
            "records": [{"content": "10.0.1.1", "disabled": False}],
            "ttl": 86400,
            "type": "A",
        },
        {
            "comments": [],
            "name": "example.com.",
            "records": [
                {
                    "content": "a.misconfigured.dns.server.invalid. hostmaster.example.com. 2025082405 10800 3600 604800 3600",
                    "disabled": False,
                }
            ],
            "ttl": 3600,
            "type": "SOA",
        },
    ],
    "serial": 2025082405,
    "slave_tsig_key_ids": [],
    "soa_edit": "",
    "soa_edit_api": "DEFAULT",
    "url": "/api/v1/servers/localhost/zones/example.com.",
}


@pytest.fixture
def example_com():
    return copy.deepcopy(example_com_zone_dict)


example_com_zone_bind = """example.com.    3600    IN      SOA     a.misconfigured.dns.server.invalid. hostmaster.example.com. 2025082405 10800 3600 604800 3600
mail.example.com.       86400   IN      MX      0 mail.example.com.
test.example.com.       86400   IN      A       10.0.0.1
test.example.com.       86400   IN      A       10.0.0.2
test2.example.com.      86400   IN      A       10.0.1.1
"""


@pytest.fixture
def example_com_bind():
    return copy.deepcopy(example_com_zone_bind)


example_org_zone_dict = {
    "account": "",
    "api_rectify": False,
    "catalog": "",
    "dnssec": False,
    "edited_serial": 2025082402,
    "id": "example.org.",
    "kind": "Native",
    "last_check": 0,
    "master_tsig_key_ids": [],
    "masters": [],
    "name": "example.org.",
    "notified_serial": 0,
    "nsec3narrow": False,
    "nsec3param": "",
    "rrsets": [
        {
            "comments": [],
            "name": "test.example.org.",
            "records": [{"content": "192.168.1.1", "disabled": False}],
            "ttl": 86400,
            "type": "A",
        },
        {
            "comments": [],
            "name": "example.org.",
            "records": [
                {
                    "content": "a.misconfigured.dns.server.invalid. hostmaster.example.org. 2025082402 10800 3600 604800 3600",
                    "disabled": False,
                }
            ],
            "ttl": 3600,
            "type": "SOA",
        },
    ],
    "serial": 2025082402,
    "slave_tsig_key_ids": [],
    "soa_edit": "",
    "soa_edit_api": "DEFAULT",
    "url": "/api/v1/servers/localhost/zones/example.org.",
}


@pytest.fixture
def example_org():
    return copy.deepcopy(example_org_zone_dict)


example_zone_list_list = [example_com_zone_dict]


@pytest.fixture
def example_zone_list():
    return copy.deepcopy(example_zone_list_list)


@pytest.fixture
def mock_utils(mocker):
    return testutils.MockUtils(mocker)


@pytest.fixture
def file_mock(mocker):
    return testutils.MockFile(mocker)


class ConditionalMock(testutils.MockUtils):
    def mock_http_get(self) -> unittest_MagicMock:
        mock_http_get = self.mocker.MagicMock(spec=requests.Response)

        def side_effect(*args, **kwargs):
            match args[0]:
                case "http://example.com/api/v1/servers/localhost/zones":
                    json_output = copy.deepcopy(example_zone_list_list)
                    status_code = 200
                case "http://example.com/api/v1/servers/localhost/zones/example.com.":
                    json_output = copy.deepcopy(example_com_zone_dict)
                    status_code = 200
                case "http://example.com/api/v1/servers/localhost/zones/example.com./export":
                    mock_http_get.text = copy.deepcopy(example_com_zone_bind)
                    json_output = {}
                    status_code = 200
                case value if "http://example.com/api/v1/servers/localhost/zones/" in value:
                    json_output = {"error": "Not found"}
                    status_code = 404
                case _:
                    raise SystemExit(f"An unexpected url-path was called: {args[0]}")
            mock_http_get.status_code = status_code
            mock_http_get.json.return_value = json_output
            mock_http_get.headers = {"Content-Type": "application/json"}
            return mock_http_get

        return self.mocker.patch("powerdns_cli.utils.http_get", side_effect=side_effect)


@pytest.fixture
def conditional_mock_utils(mocker):
    return ConditionalMock(mocker)


@pytest.mark.parametrize(
    "domain,servertype",
    (
        ("example.com", "NATIVE"),
        ("example.com", "MASTER"),
        ("example.com", "slave"),
        ("example.com..variant1", "NATIVE"),
        ("example.com..variant1", "mASTER"),
        ("example.com..variant1", "Slave"),
    ),
)
def test_zone_add_success(mock_utils, conditional_mock_utils, example_org, domain, servertype):
    get = conditional_mock_utils.mock_http_get()
    post = mock_utils.mock_http_post(201, json_output=example_org)
    runner = CliRunner()
    result = runner.invoke(
        zone_add,
        ["example.org", "NATIVE"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert "created" in json.loads(result.output)["message"]
    post.assert_called()
    get.assert_called_once()


def test_zone_add_idempotence(mock_utils, conditional_mock_utils, example_com):
    get = conditional_mock_utils.mock_http_get()
    post = mock_utils.mock_http_post(201, json_output=example_com)
    runner = CliRunner()
    result = runner.invoke(
        zone_add,
        ["example.com", "NATIVE"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert "already present" in json.loads(result.output)["message"]
    post.assert_not_called()
    get.assert_called_once()


def test_zone_add_failed(mock_utils, conditional_mock_utils, example_com):
    get = conditional_mock_utils.mock_http_get()
    post = mock_utils.mock_http_post(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        zone_add,
        ["example.org", "NATIVE"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 1
    assert "Server error" in json.loads(result.output)["error"]
    post.assert_called()
    get.assert_called_once()


def test_zone_delete_success(mock_utils, conditional_mock_utils, example_org):
    get = conditional_mock_utils.mock_http_get()
    delete = mock_utils.mock_http_delete(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        zone_delete,
        ["example.com", "-f"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert "deleted" in json.loads(result.output)["message"]
    delete.assert_called()
    get.assert_called_once()


def test_zone_delete_idempotence(mock_utils, conditional_mock_utils, example_com):
    get = conditional_mock_utils.mock_http_get()
    delete = mock_utils.mock_http_delete(204, text_output="")
    runner = CliRunner()
    result = runner.invoke(
        zone_delete,
        ["example.org"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert "already absent" in json.loads(result.output)["message"]
    delete.assert_not_called()
    get.assert_called_once()


def test_zone_delete_failed(mock_utils, conditional_mock_utils, example_com):
    get = conditional_mock_utils.mock_http_get()
    delete = mock_utils.mock_http_delete(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        zone_delete,
        ["example.com", "-f"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 1
    assert "Server error" in json.loads(result.output)["error"]
    delete.assert_called()
    get.assert_called_once()


def test_zone_import_success(
    mocker,
    mock_utils,
    file_mock,
    example_com,
):
    mocker.patch("powerdns_cli.utils.read_settings_from_upstream", return_value=example_com)
    post = mock_utils.mock_http_post(201, json_output={"message": "OK"})
    delete = mock_utils.mock_http_delete(204, json_output={"message": "OK"})
    file_mock.mock_settings_import(
        {
            "account": "test123",
            "api_rectify": False,
            "catalog": "",
            "dnssec": False,
            "edited_serial": 2025082405,
            "id": "example.com.",
            "kind": "Master",
            "master_tsig_key_ids": [],
            "masters": [],
            "name": "example.com.",
            "nsec3narrow": False,
            "nsec3param": "",
            "serial": 2025082405,
            "slave_tsig_key_ids": [],
            "soa_edit": "",
            "soa_edit_api": "DEFAULT",
            "url": "/api/v1/servers/localhost/zones/example.com.",
        }
    )
    added_content = {
        "account": "test123",
        "api_rectify": False,
        "catalog": "",
        "dnssec": False,
        "edited_serial": 2025082405,
        "id": "example.com.",
        "kind": "Master",
        "master_tsig_key_ids": [],
        "masters": [],
        "name": "example.com.",
        "nsec3narrow": False,
        "nsec3param": "",
        "serial": 2025082405,
        "slave_tsig_key_ids": [],
        "soa_edit": "",
        "soa_edit_api": "DEFAULT",
        "url": "/api/v1/servers/localhost/zones/example.com.",
    }
    runner = CliRunner()
    result = runner.invoke(
        zone_import,
        ["testfile", "--force"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert "imported" in json.loads(result.output)["message"]
    assert post.call_count == 1
    assert delete.call_count == 1
    assert added_content == post.call_args_list[0].kwargs["payload"]


def test_zone_import_merge_success(
    mocker,
    mock_utils,
    file_mock,
    example_com,
):
    mocker.patch("powerdns_cli.utils.read_settings_from_upstream", return_value=example_com)
    post = mock_utils.mock_http_post(201, json_output={"message": "OK"})
    delete = mock_utils.mock_http_delete(204, json_output={"message": "OK"})
    file_mock.mock_settings_import(
        {
            "account": "test123",
            "api_rectify": False,
            "catalog": "",
            "dnssec": False,
            "edited_serial": 2025082405,
            "id": "example.com.",
            "kind": "Master",
            "master_tsig_key_ids": [],
            "masters": [],
            "name": "example.com.",
            "nsec3narrow": False,
            "nsec3param": "",
            "serial": 2025082405,
            "slave_tsig_key_ids": [],
            "soa_edit": "",
            "soa_edit_api": "DEFAULT",
            "url": "/api/v1/servers/localhost/zones/example.com.",
        }
    )
    added_content = {
        "account": "test123",
        "api_rectify": False,
        "catalog": "",
        "dnssec": False,
        "edited_serial": 2025082405,
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
            {
                "comments": [],
                "name": "test2.example.com.",
                "records": [{"content": "10.0.1.1", "disabled": False}],
                "ttl": 86400,
                "type": "A",
            },
            {
                "comments": [],
                "name": "example.com.",
                "records": [
                    {
                        "content": "a.misconfigured.dns.server.invalid. hostmaster.example.com. 2025082405 10800 3600 604800 3600",
                        "disabled": False,
                    }
                ],
                "ttl": 3600,
                "type": "SOA",
            },
        ],
        "serial": 2025082405,
        "slave_tsig_key_ids": [],
        "soa_edit": "",
        "soa_edit_api": "DEFAULT",
        "url": "/api/v1/servers/localhost/zones/example.com.",
    }
    runner = CliRunner()
    result = runner.invoke(
        zone_import,
        ["testfile", "--force", "--merge"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert "imported" in json.loads(result.output)["message"]
    assert post.call_count == 1
    assert delete.call_count == 1
    assert added_content == post.call_args_list[0].kwargs["payload"]


def test_zone_import_idempotence(
    mocker,
    mock_utils,
    file_mock,
    example_com,
):
    mocker.patch("powerdns_cli.utils.read_settings_from_upstream", return_value=example_com)
    file_mock.mock_settings_import(
        {
            "account": "",
            "api_rectify": False,
            "catalog": "",
            "dnssec": False,
            "edited_serial": 2025082405,
            "id": "example.com.",
            "kind": "Master",
            "master_tsig_key_ids": [],
            "masters": [],
            "name": "example.com.",
            "nsec3narrow": False,
            "nsec3param": "",
            "serial": 2025082405,
            "slave_tsig_key_ids": [],
            "soa_edit": "",
            "soa_edit_api": "DEFAULT",
            "url": "/api/v1/servers/localhost/zones/example.com.",
        }
    )
    runner = CliRunner()
    result = runner.invoke(
        zone_import,
        ["testfile", "--force"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert "already" in json.loads(result.output)["message"]


def test_zone_import_invalid_file(
    mocker,
    mock_utils,
    file_mock,
    example_com,
):
    mocker.patch("powerdns_cli.utils.read_settings_from_upstream", return_value=example_com)
    file_mock.mock_settings_import(
        {
            "account": "",
            "api_rectify": False,
            "catalog": "",
            "dnssec": False,
            "edited_serial": 2025082405,
            "kind": "Master",
            "master_tsig_key_ids": [],
            "masters": [],
            "nsec3narrow": False,
            "nsec3param": "",
            "serial": 2025082405,
            "slave_tsig_key_ids": [],
            "soa_edit": "",
            "soa_edit_api": "DEFAULT",
            "url": "/api/v1/servers/localhost/zones/example.com.",
        }
    )
    runner = CliRunner()
    result = runner.invoke(
        zone_import,
        ["testfile", "--force"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 1
    assert "Either" in json.loads(result.output)["error"]


def test_zone_import_no_confirm(
    mocker,
    mock_utils,
    file_mock,
    example_com,
):
    mocker.patch("powerdns_cli.utils.read_settings_from_upstream", return_value=example_com)
    file_mock.mock_settings_import(
        {
            "account": "test123",
            "api_rectify": False,
            "catalog": "",
            "dnssec": False,
            "edited_serial": 2025082405,
            "id": "example.com.",
            "kind": "Master",
            "master_tsig_key_ids": [],
            "masters": [],
            "name": "example.com.",
            "nsec3narrow": False,
            "nsec3param": "",
            "serial": 2025082405,
            "slave_tsig_key_ids": [],
            "soa_edit": "",
            "soa_edit_api": "DEFAULT",
            "url": "/api/v1/servers/localhost/zones/example.com.",
        }
    )
    runner = CliRunner()
    result = runner.invoke(
        zone_import,
        ["testfile"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 1
    assert "Aborted" in result.output


def test_zone_list_success(conditional_mock_utils, example_zone_list):
    get = conditional_mock_utils.mock_http_get()
    runner = CliRunner()
    result = runner.invoke(
        zone_list,
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == example_zone_list
    get.assert_called_once()


def test_zone_list_failed(mock_utils, example_com):
    get = mock_utils.mock_http_get(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        zone_list,
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 1
    assert "Server error" in json.loads(result.output)["error"]
    get.assert_called_once()


def test_zone_export_success(mock_utils, conditional_mock_utils, example_com):
    get = conditional_mock_utils.mock_http_get()
    runner = CliRunner()
    result = runner.invoke(
        zone_export,
        ["example.com"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == example_com
    get.assert_called_once()


def test_zone_export_bind(mock_utils, conditional_mock_utils, example_com_bind):
    get = conditional_mock_utils.mock_http_get()
    runner = CliRunner()
    result = runner.invoke(
        zone_export,
        ["example.com", "-b"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert result.output.rstrip() == example_com_bind.rstrip()
    get.assert_called_once()


def test_zone_export_failed(mock_utils):
    get = mock_utils.mock_http_get(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        zone_export,
        ["example.org"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 1
    assert json.loads(result.output) == {"error": "Server error"}
    get.assert_called_once()


def test_zone_rectify_success(mock_utils):
    put = mock_utils.mock_http_put(200, json_output={"result": "Rectified"})
    runner = CliRunner()
    result = runner.invoke(
        zone_rectify,
        ["example.com"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == {"result": "Rectified"}
    put.assert_called_once()


def test_zone_rectify_failed(mock_utils):
    put = mock_utils.mock_http_put(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        zone_rectify,
        ["example.com"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 1
    assert json.loads(result.output) == {"error": "Server error"}
    put.assert_called_once()


def test_zone_notify_success(mock_utils):
    put = mock_utils.mock_http_put(200, json_output={"result": "Notification queued"})
    runner = CliRunner()
    result = runner.invoke(
        zone_notify,
        ["example.com"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == {"result": "Notification queued"}
    put.assert_called_once()


def test_zone_notify_failed(mock_utils):
    put = mock_utils.mock_http_put(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        zone_notify,
        ["example.com"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 1
    assert json.loads(result.output) == {"error": "Server error"}
    put.assert_called_once()


def test_zone_flush_success(mock_utils):
    put = mock_utils.mock_http_put(200, json_output={"count": 1, "result": "Flushed cache."})
    runner = CliRunner()
    result = runner.invoke(
        zone_flush_cache,
        ["example.com"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == {"count": 1, "result": "Flushed cache."}
    put.assert_called_once()


def test_zone_flush_failed(mock_utils):
    put = mock_utils.mock_http_put(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        zone_flush_cache,
        ["example.com"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 1
    assert json.loads(result.output) == {"error": "Server error"}
    put.assert_called_once()


def test_zone_search_success(mock_utils):
    search_output = copy.deepcopy(
        [
            {"name": "example.org.", "object_type": "zone", "zone_id": "example.org."},
            {
                "content": "a.misconfigured.dns.server.invalid. hostmaster.example.org. 2025082401 10800 3600 604800 3600",
                "disabled": False,
                "name": "example.org.",
                "object_type": "record",
                "ttl": 3600,
                "type": "SOA",
                "zone": "example.org.",
                "zone_id": "example.org.",
            },
        ]
    )
    get = mock_utils.mock_http_get(200, json_output=search_output)
    runner = CliRunner()
    result = runner.invoke(
        zone_search,
        ["example*"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 0
    assert json.loads(result.output) == [
        {"name": "example.org.", "object_type": "zone", "zone_id": "example.org."},
        {
            "content": "a.misconfigured.dns.server.invalid. hostmaster.example.org. 2025082401 10800 3600 604800 3600",
            "disabled": False,
            "name": "example.org.",
            "object_type": "record",
            "ttl": 3600,
            "type": "SOA",
            "zone": "example.org.",
            "zone_id": "example.org.",
        },
    ]
    get.assert_called_once()


def test_zone_search_failed(mock_utils):
    get = mock_utils.mock_http_get(500, json_output={"error": "Server error"})
    runner = CliRunner()
    result = runner.invoke(
        zone_search,
        ["example.com"],
        obj={"apihost": "http://example.com"},
    )
    assert result.exit_code == 1
    assert json.loads(result.output) == {"error": "Server error"}
    get.assert_called_once()
