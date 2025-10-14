import json
import logging
from collections import OrderedDict
from unittest.mock import MagicMock

import click
import pytest
import requests

from powerdns_cli.utils.logger import ResultHandler


@pytest.fixture
def result_handler():
    return ResultHandler()


def test_result_handler_init(result_handler):
    assert result_handler.result == {
        "logs": [],
        "message": "",
        "success": None,
        "http": [],
        "data": None,
    }


def test_emit(result_handler, mocker):
    record = logging.LogRecord("name", logging.INFO, "pathname", 0, "msg", (), None)
    result_handler.setFormatter(logging.Formatter("%(message)s"))
    result_handler.emit(record)
    assert result_handler.result["logs"] == ["msg"]


def test_set_data_with_json(result_handler, mocker):
    mock_response = mocker.Mock(spec=requests.Response)
    mock_response.json.return_value = {"key": "value"}
    result_handler.set_data(mock_response)
    assert result_handler.result["data"] == {"key": "value"}


def test_set_data_with_text(result_handler, mocker):
    mock_response = mocker.Mock(spec=requests.Response)
    mock_response.json.side_effect = json.JSONDecodeError("Expecting value", "", 0)
    mock_response.text = "plain text"
    result_handler.set_data(mock_response)
    assert result_handler.result["data"] == "plain text"


def test_set_message(result_handler):
    result_handler.set_message("test message")
    assert result_handler.result["message"] == "test message"


def test_log_http_data_with_json(result_handler, mocker):
    mock_response = mocker.Mock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.reason = "OK"
    mock_response.json.return_value = {"key": "value"}
    mock_response.request = MagicMock()
    mock_response.request.method = "GET"
    mock_response.request.url = "http://example.com"
    mock_response.request.body = json.dumps({"body": "data"})

    mock_ctx = mocker.Mock(spec=click.Context)
    mock_ctx.obj = MagicMock()
    mock_ctx.obj.config = {"debug": True}

    result_handler.log_http_data(mock_ctx, mock_response)
    assert result_handler.result["http"] == [
        {
            "request": {
                "method": "GET",
                "url": "http://example.com",
                "body": {"body": "data"},
            },
            "response": {
                "status_code": 200,
                "reason": "OK",
                "json": {"key": "value"},
                "text": "",
            },
        }
    ]


def test_log_http_data_with_text(result_handler, mocker):
    mock_response = mocker.Mock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.reason = "OK"
    mock_response.json.side_effect = json.JSONDecodeError("Expecting value", "", 0)
    mock_response.text = "plain text"
    mock_response.request = MagicMock()
    mock_response.request.method = "GET"
    mock_response.request.url = "http://example.com"
    mock_response.request.body = None

    mock_ctx = mocker.Mock(spec=click.Context)
    mock_ctx.obj = MagicMock()
    mock_ctx.obj.config = {"debug": True}

    result_handler.log_http_data(mock_ctx, mock_response)
    assert result_handler.result["http"] == [
        {
            "request": {
                "method": "GET",
                "url": "http://example.com",
                "body": "",
            },
            "response": {
                "status_code": 200,
                "reason": "OK",
                "json": {},
                "text": "plain text",
            },
        }
    ]


def test_log_http_data_no_debug(result_handler):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.reason = "OK"
    mock_response.json.return_value = {"key": "value"}
    mock_response.request = MagicMock()
    mock_response.request.method = "GET"
    mock_response.request.url = "http://example.com"
    mock_response.request.body = json.dumps({"body": "data"})

    mock_ctx = MagicMock(spec=click.Context)
    mock_ctx.obj = MagicMock()
    mock_ctx.obj.config = {"debug": False}

    result_handler.log_http_data(mock_ctx, mock_response)
    assert result_handler.result["http"] == [
        {
            "request": {
                "method": "GET",
                "url": "http://example.com",
            },
            "response": {
                "status_code": 200,
                "reason": "OK",
                "json": {"key": "value"},
                "text": "",
            },
        }
    ]


def test_set_success(result_handler):
    result_handler.set_success(True)
    assert result_handler.result["success"] is True
    result_handler.set_success(False)
    assert result_handler.result["success"] is False


def test_get_result(result_handler):
    result_handler.set_message("test message")
    result_handler.set_success(True)
    result = result_handler.get_result()
    assert isinstance(result, OrderedDict)
    assert list(result.keys()) == [
        "logs",
        "http",
        "data",
        "success",
        "message",
    ]
    assert result["message"] == "test message"
    assert result["success"] is True
