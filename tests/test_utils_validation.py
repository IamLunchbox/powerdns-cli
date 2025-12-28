import os
from unittest.mock import MagicMock

import click
import pytest

from powerdns_cli.utils.validation import ContextObj, DefaultCommand, validate_dns_zone


def test_valid_zone():
    canonical_zone = validate_dns_zone(None, "example.com.")
    converted_zone = validate_dns_zone(None, "example.com")
    assert converted_zone == "example.com."
    assert canonical_zone == "example.com."


def test_invalid_zone():
    for bad_zone in ("-example.com.", "example.com..", "^example.com.", "example"):
        with pytest.raises(click.BadParameter):
            validate_dns_zone(None, bad_zone)


@pytest.fixture
def mock_ctx():
    ctx = MagicMock(spec=ContextObj)
    ctx.params = {
        "url": "http://localhost:8080",
        "apikey": "test-api-key",
        "json_output": False,
        "insecure": False,
        "debug": None,
        "api_version": None,
        "server_id": None,
        "timeout": None,
    }
    ctx.obj = MagicMock()
    ctx.obj.logger = MagicMock()
    ctx.obj.config = {}
    return ctx


@pytest.mark.parametrize(
    "dirname,filename,patch_home",
    (
        ("powerdns_cli", "config.toml", True),  # patch_home since config_dir is derived from $HOME
        ("powerdns-cli", "config.toml", True),
        ("powerdns_cli", "configuration.toml", True),
        ("powerdns-cli", "configuration.toml", True),
        ("", ".powerdns-cli.conf", True),
        ("", ".powerdns-cli.conf", True),
        ("", ".powerdns-cli.conf", False),
        ("", ".powerdns-cli.conf", False),
    ),
)
def test_parse_options_with_toml_config(
    tmp_path, mock_ctx, patch_home, dirname: str, filename: str, monkeypatch
):
    # Create a temporary TOML config file
    mock_ctx.params = {
        "url": None,
        "apikey": None,
        "json_output": None,
        "insecure": None,
        "debug": None,
        "api_version": None,
        "server_id": None,
        "timeout": None,
    }
    if dirname:
        os.makedirs(tmp_path / ".config" / dirname, exist_ok=True)
        with open(tmp_path / ".config" / dirname / filename, "w") as f:
            f.write(
                """
                url="http://config-host:8080"
                apikey="config-api-key"
                json=true
                insecure=true
                debug=true
                api-version=5
                server-id="mydnshost"
                """
            )
    else:
        with open(tmp_path / filename, "w") as f:
            f.write(
                """
                url="http://config-host:8080"
                apikey="config-api-key"
                json=true
                insecure=true
                debug=true
                api-version=5
                server-id="mydnshost"
                """
            )
    mock_ctx.params["apikey"] = None
    mock_ctx.params["url"] = None

    # patching user_config_path did not work at all,
    # but it derives the location from HOME
    if patch_home:
        monkeypatch.setenv("HOME", str(tmp_path))
    elif not patch_home and not dirname:
        monkeypatch.chdir(tmp_path)

    DefaultCommand.parse_options(mock_ctx, [])

    # Assert that the config was loaded from the TOML file
    expected_values = {
        "apihost": "http://config-host:8080",
        "key": "config-api-key",
        "debug": True,
        "json": True,
        "api_version": 5,
        "insecure": True,
        "server_id": "mydnshost",
    }
    for key, val in expected_values.items():
        assert mock_ctx.obj.config[key] == val


def test_partial_override_from_config(tmp_path, mock_ctx, monkeypatch):
    # Create a temporary TOML config file
    os.makedirs(tmp_path / ".config" / "powerdns_cli", exist_ok=True)
    with open(tmp_path / ".config" / "powerdns_cli" / "config.toml", "w") as f:
        f.write(
            """
            url="http://invalid-host:8081"
            apikey="config-api-key"
            json=true
            insecure=true
            debug=true
            api-version=5
            server-id="mydnshost"
            """
        )
    mock_ctx.params["apikey"] = None
    mock_ctx.params["url"] = "http://config-host:8080"

    # patching user_config_path did not work at all,
    # but it derives the location from HOME
    monkeypatch.setenv("HOME", str(tmp_path))

    DefaultCommand.parse_options(mock_ctx, [])

    # Assert that the config was loaded from the TOML file
    expected_values = {
        "apihost": "http://config-host:8080",
        "key": "config-api-key",
        "debug": True,
        "json": False,
        "api_version": 5,
        "insecure": False,
        "server_id": "mydnshost",
    }
    for key, val in expected_values.items():
        if not mock_ctx.obj.config[key] == val:
            raise AssertionError(
                f"Value of '{key}' did not match, {mock_ctx.obj.config[key]} instead of {val}"
            )


def test_parse_options_without_toml_config(mock_ctx, monkeypatch, tmp_path):
    # Mock user_config_path to return a non-existent file
    monkeypatch.setenv("HOME", str(tmp_path))
    DefaultCommand.parse_options(mock_ctx, [])

    # Assert that the config was set from CLI params
    assert mock_ctx.obj.config["apihost"] == "http://localhost:8080"
    assert mock_ctx.obj.config["key"] == "test-api-key"


def test_parse_options_missing_required_params(mock_ctx):
    # Simulate missing apikey
    mock_ctx.params["apikey"] = None
    with pytest.raises(SystemExit):
        DefaultCommand.parse_options(mock_ctx, [])

    # Simulate missing URL
    mock_ctx.params["apikey"] = "test-api-key"
    mock_ctx.params["url"] = None
    with pytest.raises(SystemExit):
        DefaultCommand.parse_options(mock_ctx, [])
