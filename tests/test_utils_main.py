import json
from typing import Any, NoReturn
from unittest.mock import MagicMock

import click
import pytest

from powerdns_cli.utils.main import exit_cli


@pytest.fixture
def mock_ctx():
    mock_ctx = MagicMock(spec=click.Context)
    mock_ctx.obj = MagicMock()
    mock_ctx.obj.config = {"json": False}
    mock_ctx.obj.handler = MagicMock()
    mock_ctx.obj.handler.get_result.return_value = {
        "success": True,
        "data": {"key": "value"},
        "message": "Success",
    }
    return mock_ctx


def test_exit_cli_json_config(mocker, mock_ctx) -> None:
    mocker.patch("click.echo")
    mock_ctx.obj.config = {"json": True}
    with pytest.raises(SystemExit) as excinfo:
        exit_cli(mock_ctx)
    assert excinfo.value.code == 0
    click.echo.assert_called_once_with(json.dumps(mock_ctx.obj.handler.get_result(), indent=4))


def test_exit_cli_print_data(mock_ctx: click.Context, mocker) -> None:
    mocker.patch("click.echo")
    with pytest.raises(SystemExit) as excinfo:
        exit_cli(mock_ctx, print_data=True)
    assert excinfo.value.code == 0
    click.echo.assert_called_once_with(
        json.dumps(mock_ctx.obj.handler.get_result()["data"], indent=4)
    )


def test_exit_cli_message(mock_ctx: click.Context, mocker) -> None:
    mocker.patch("click.echo")
    with pytest.raises(SystemExit) as excinfo:
        exit_cli(mock_ctx)
    assert excinfo.value.code == 0
    click.echo.assert_called_once_with(mock_ctx.obj.handler.get_result()["message"])


def test_exit_cli_failure(mock_ctx: click.Context, mocker) -> None:
    mock_ctx.obj.handler.get_result.return_value = {
        "success": False,
        "data": {"key": "value"},
        "message": "Failure",
    }
    mocker.patch("click.echo")

    with pytest.raises(SystemExit) as excinfo:
        exit_cli(mock_ctx)
    assert excinfo.value.code == 1
    click.echo.assert_called_once_with(mock_ctx.obj.handler.get_result()["message"])
