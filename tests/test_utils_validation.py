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
    }
    ctx.obj = MagicMock()
    ctx.obj.logger = MagicMock()
    ctx.obj.config = {}
    return ctx


@pytest.mark.parametrize(
    "dirname,filename",
    (
        ("powerdns_cli", "config.toml"),
        ("powerdns-cli", "config.toml"),
        ("powerdns_cli", "configuration.toml"),
        ("powerdns-cli", "configuration.toml"),
        ("", ".powerdns-cli.conf"),
        ("", ".powerdns-cli.conf"),
    ),
)
def test_parse_options_with_toml_config(tmp_path, mock_ctx, mocker, dirname: str, filename: str):
    # Create a temporary TOML config file
    mock_ctx.params = {
        "url": None,
        "apikey": None,
        "json_output": None,
        "insecure": None,
        "debug": None,
        "api_version": None,
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
                """
            )
    mock_ctx.params["apikey"] = None
    mock_ctx.params["url"] = None

    # patching user_config_path did not work at all,
    # but it derives the location from HOME
    mocker.patch.dict(os.environ, {"HOME": str(tmp_path)})

    DefaultCommand.parse_options(mock_ctx, [])

    # Assert that the config was loaded from the TOML file
    expected_values = {
        "apihost": "http://config-host:8080",
        "key": "config-api-key",
        "debug": True,
        "json": True,
        "api_version": 5,
        "insecure": True,
    }
    for key, val in expected_values.items():
        assert mock_ctx.obj.config[key] == val


def test_partial_override_from_config(tmp_path, mock_ctx, mocker):
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
            """
        )
    mock_ctx.params["apikey"] = None
    mock_ctx.params["url"] = "http://config-host:8080"

    # patching user_config_path did not work at all,
    # but it derives the location from HOME
    mocker.patch.dict(os.environ, {"HOME": str(tmp_path)})

    DefaultCommand.parse_options(mock_ctx, [])

    # Assert that the config was loaded from the TOML file
    expected_values = {
        "apihost": "http://config-host:8080",
        "key": "config-api-key",
        "debug": True,
        "json": False,
        "api_version": 5,
        "insecure": False,
    }
    for key, val in expected_values.items():
        if not mock_ctx.obj.config[key] == val:
            raise AssertionError(
                f"Value of '{key}' did not match, {mock_ctx.obj.config[key]} instead of {val}"
            )


def test_parse_options_without_toml_config(mock_ctx, mocker, tmp_path):
    # Mock user_config_path to return a non-existent file
    mocker.patch.dict(os.environ, {"HOME": str(tmp_path)})
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
