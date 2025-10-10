import json

from click.testing import CliRunner
from powerdns_cli_test_utils.testutils import mock_utils, testenvironment, testobject

from powerdns_cli.commands.config import config_export, config_list, config_stats


def test_config_export_success(mock_utils, testobject):
    json_output = [
        {"name": "8bit-dns", "type": "ConfigSetting", "value": "no"},
        {"name": "allow-axfr-ips", "type": "ConfigSetting", "value": "127.0.0.0/8,::1"},
    ]
    get = mock_utils.mock_http_get(200, json_output=json_output)
    runner = CliRunner()
    result = runner.invoke(config_export, obj=testobject, env=testenvironment)
    assert result.exit_code == 0
    assert json.loads(result.output)["data"] == json_output
    get.assert_called()


def test_config_export_failure(mock_utils, testobject):
    get = mock_utils.mock_http_get(500, {"error": "Internal server error"})
    runner = CliRunner()
    result = runner.invoke(config_export, obj=testobject, env=testenvironment)
    assert result.exit_code == 1
    get.assert_called()


def test_config_list_success(mock_utils, testobject):
    json_output = [{"id": "localhost", "daemon_type": "authoritative"}]
    get = mock_utils.mock_http_get(200, json_output=json_output)
    runner = CliRunner()
    result = runner.invoke(config_list, obj=testobject, env=testenvironment)
    assert result.exit_code == 0
    assert json.loads(result.output)["data"] == json_output
    get.assert_called()


def test_config_list_servers_failure(mock_utils, testobject):
    get = mock_utils.mock_http_get(401, {"error": "Unauthorized"})
    runner = CliRunner()
    result = runner.invoke(config_list, obj=testobject, env=testenvironment)
    assert result.exit_code == 1
    get.assert_called()


def test_config_stats_success(mock_utils, testobject):
    json_output = [
        {"name": "backend-latency", "type": "StatisticItem", "value": "0"},
        {"name": "backend-queries", "type": "StatisticItem", "value": "9"},
        {"name": "cache-latency", "type": "StatisticItem", "value": "0"},
    ]
    get = mock_utils.mock_http_get(200, json_output=json_output)
    runner = CliRunner()
    result = runner.invoke(config_stats, obj=testobject, env=testenvironment)
    assert result.exit_code == 0
    assert json.loads(result.output)["data"] == json_output
    get.assert_called()


def test_config_stats_failure(mock_utils, testobject):
    get = mock_utils.mock_http_get(503, {"error": "Service unavailable"})
    runner = CliRunner()
    result = runner.invoke(config_stats, obj=testobject, env=testenvironment)
    assert result.exit_code == 1
    get.assert_called()
