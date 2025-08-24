import json
import copy
import pytest
from click.testing import CliRunner
from powerdns_cli.powerdns_cli import (
    zone_add,
    zone_delete,
    zone_list,
    zone_export,
    zone_notify,
    zone_search,
    zone_rectify,
    zone_flush_cache,
)
from powerdns_cli_test_utils import testutils
from unittest.mock import MagicMock as unittest_MagicMock
import requests


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
def zone_list():
    return copy.deepcopy(example_zone_list_list)


@pytest.fixture
def mock_utils(mocker):
    return testutils.MockUtils(mocker)


class ConditionalMock(testutils.MockUtils):
    def mock_http_get(self) -> unittest_MagicMock:
        def side_effect(*args, **kwargs):
            match args[0]:
                case "http://example.com/api/v1/servers/localhost/zones":
                    json_output = copy.deepcopy(example_zone_list_list)
                    status_code = 200
                case "http://example.com/api/v1/servers/localhost/zones/example.com.":
                    json_output = copy.deepcopy(example_com_zone_dict)
                    status_code = 200
                case "http://example.com/api/v1/servers/localhost/zones/example.com./export":
                    json_output = copy.deepcopy(example_com_zone_bind)
                    status_code = 200
                case (
                    value
                ) if "http://example.com/api/v1/servers/localhost/zones/" in value:
                    json_output = {"error": "Not found"}
                    status_code = 404
                case _:
                    raise NotImplementedError(
                        f"An unexpected url-path was called: {args[0]}"
                    )
            mock_http_get = self.mocker.MagicMock(spec=requests.Response)
            mock_http_get.status_code = status_code
            mock_http_get.json.return_value = json_output
            mock_http_get.headers = {"Content-Type": "application/json"}
            return mock_http_get

        return self.mocker.patch("powerdns_cli.utils.http_get", side_effect=side_effect)


@pytest.fixture
def conditional_mock_utils(mocker):
    return ConditionalMock(mocker)


def test_zone_add_success(mock_utils, conditional_mock_utils, example_org):
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
