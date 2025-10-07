"""Utilities library for the main cli functions"""

import json
import logging
from typing import Any, NoReturn, TextIO

import click
import requests

from . import logger

# pylint: disable=too-few-public-methods


class ContextObj:
    """A context object for managing logging, configuration, and session state.

    Attributes:
        handler: A custom logging handler for collecting logs and results.
        logger: A logger instance for emitting log messages.
        config: A dictionary for storing configuration settings.
        session: A placeholder for a session object, initially None.
    """

    def __init__(self) -> None:
        """Initializes the ContextObj with a logger, handler, and default configuration."""
        self.handler = logger.ResultHandler()
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        self.handler.setFormatter(formatter)
        self.logger = logging.getLogger("cli_logger")
        self.logger.addHandler(self.handler)
        self.logger.setLevel(logging.DEBUG)
        self.config: dict[str, Any] = {}
        self.session: requests.Session | None = None


# pylint: enable=too-few-public-methods


def exit_cli(ctx: click.Context, print_data: bool = False) -> NoReturn:
    """Exits the CLI, optionally printing the result in JSON or a specific response field.

    Args:
        ctx: The Click context object containing the handler and configuration.
        print_data: If True, prints the response data instead of the message. Defaults to False.

    Raises:
        SystemExit: Always raised with the provided exit code.
    """
    if ctx.obj.config["json"]:
        click.echo(json.dumps(ctx.obj.handler.get_result(), indent=4))
    elif print_data:
        click.echo(json.dumps(ctx.obj.handler.get_result()["data"], indent=4))
    else:
        click.echo(ctx.obj.handler.get_result()["message"])
    if ctx.obj.handler.get_result()["success"]:
        raise SystemExit(0)
    raise SystemExit(1)


def exit_action(
    ctx: click.Context,
    success: bool,
    response: requests.Response = None,
    message: str | None = None,
    print_data: bool = False,
) -> NoReturn:
    """
    Handles action exit logic based on HTTP response status codes.

    Sets the handler's status, message, and data, then exits the CLI.
    The exit status is determined by whether the response's status code
    matches the expected status code(s).

    Args:
        ctx: Click context object.
        success: Declare if action failed or succeeded.
        response: HTTP response object.
        message: Optional message to set in the handler.
        print_data: If True, sets the response data in the handler.
    """
    if message:
        ctx.obj.handler.set_message(message)
    if print_data:
        ctx.obj.handler.set_data(response)
    ctx.obj.handler.set_success(success)
    exit_cli(ctx, print_data=print_data)


def make_canonical(zone: str) -> str:
    """Ensure a DNS zone name ends with a trailing dot.

    Args:
        zone: The DNS zone name (e.g., "example.com").

    Returns:
        The zone name with a trailing dot if not already present.
    """
    return zone if zone.endswith(".") else zone + "."


def confirm(message: str, force: bool) -> None:
    """Confirmation function to keep users from doing potentially dangerous actions.
    Uses the force flag to determine if a manual confirmation is required."""
    if not force:
        click.echo(message)
        confirmation = input()
        if confirmation not in ("y", "Y", "YES", "yes", "Yes"):
            click.echo("Aborting")
            raise SystemExit(1)


def create_output(
    content: requests.Response,
    exp_status_code: tuple[int, ...],
    output_text: bool = None,
    optional_json: dict = None,
) -> bool:
    """Helper function to print a message in the appropriate format.
    Is needed since the powerdns api outputs different content types, not
    json all the time. Sometimes output is empty (each 204 response) or
    needs to be plain text - when you want to the BIND / AFXR export."""
    if content.status_code in exp_status_code and output_text:
        click.echo(content.text)
        return True
    if content.status_code in exp_status_code and optional_json:
        click.echo(json.dumps(optional_json, indent=4))
        return True
    if content.status_code in exp_status_code:
        click.echo(json.dumps(content.json(), indent=4))
        return True
    if content.headers.get("Content-Type", "").startswith("text/plain"):
        click.echo(json.dumps({"error": content.text}))
        return False
    # Catch unexpected empty responses
    try:
        click.echo(json.dumps(content.json(), indent=4))
    except json.JSONDecodeError:
        print_output({"error": f"Non json response from server with status {content.status_code}"})
    return False


def http_delete(uri: str, ctx: click.Context, params: dict = None) -> requests.Response:
    """HTTP DELETE request"""
    try:
        request = ctx.obj.session.delete(uri, params=params, timeout=10)
        ctx.obj.handler.set_response_data(request, ctx)
        return request
    except requests.RequestException as e:
        raise SystemExit(json.dumps({"error": f"Request error: {e}"}, indent=4)) from e


def http_get(uri: str, ctx: click.Context, params: dict = None) -> requests.Response:
    """HTTP GET request"""
    try:
        request = ctx.obj.session.get(uri, params=params, timeout=10)
        ctx.obj.handler.set_response_data(request, ctx)
        return request
    except requests.RequestException as e:
        raise SystemExit(json.dumps({"error": f"Request error: {e}"}, indent=4)) from e


def http_patch(uri: str, ctx: click.Context, payload: dict) -> requests.Response:
    """HTTP PATCH request"""
    try:
        request = ctx.obj.session.patch(uri, json=payload, timeout=10)
        ctx.obj.handler.set_response_data(request, ctx)
        return request
    except requests.RequestException as e:
        raise SystemExit(json.dumps({"error": f"Request error: {e}"}, indent=4)) from e


def http_post(uri: str, ctx: click.Context, payload: dict) -> requests.Response:
    """HTTP POST request"""
    try:
        request = ctx.obj.session.post(uri, json=payload, timeout=10)
        ctx.obj.handler.set_response_data(request, ctx)
        return request
    except requests.RequestException as e:
        raise SystemExit(json.dumps({"error": f"Request error: {e}"}, indent=4)) from e


def http_put(
    uri: str, ctx: click.Context, payload: dict = None, params: dict = None
) -> requests.Response:
    """HTTP PUT request"""
    try:
        request = ctx.obj.session.put(uri, json=payload, params=params, timeout=10)
        ctx.obj.handler.set_response_data(request, ctx)
        return request
    except requests.RequestException as e:
        raise SystemExit(json.dumps({"error": f"Request error: {e}"}, indent=4)) from e


def make_dnsname(name: str, zone: str) -> str:
    """Returns either the combination or zone or just a zone when @ is provided as name"""
    if name == "@":
        return zone
    return f"{name}.{zone}"


def open_spec(action: str) -> SystemExit:
    """Opens the api spec on https://redocly.github.io with your default browser"""
    action = action.lower()
    match action:
        case "autoprimary":
            tag = "/autoprimary"
        case "cryptokey":
            tag = "/zonecryptokey"
        case "config":
            tag = "/config"
        case "metadata":
            tag = "/zonemetadata"
        case "network":
            tag = "/networks"
        case "record":
            tag = "/zones/operation/patchZone"
        case "search":
            tag = "/search"
        case "tsigkey":
            tag = "/tsigkey"
        case "view":
            tag = "/views"
        case "zone":
            tag = "/zones"
        case _:
            tag = ""
    url = (
        f"https://redocly.github.io/redoc/?url="
        f"https://raw.githubusercontent.com/PowerDNS/pdns/"
        f"refs/heads/master/docs/http-api/swagger/authoritative-api-swagger.yaml"
        f"#tag{tag}"
    )
    raise SystemExit(click.launch(url))


def extract_file(input_file: TextIO) -> dict | list:
    """Extracts a json object from a file input and returns it."""
    try:
        return_object = json.load(input_file)
    except (json.JSONDecodeError, ValueError, TypeError) as e:
        print_output({"error": f"Loading the file failed with {e}"})
        raise SystemExit(1) from e
    if not isinstance(return_object, (dict, list)):
        raise ValueError("utils.extract file returned an unexpected filetype")
    return return_object


def read_settings_from_upstream(uri: str, ctx: click.Context) -> dict | list:
    """Fetch settings from upstream URI with optional nested key extraction.

    Args:
        uri: Endpoint URL to fetch settings from
        ctx: Click context for HTTP requests

    Returns:
        Dictionary or list of settings. Empty dictionary if request returns 404.

    Raises:
        SystemExit: When nested_key doesn't exist in response
    """
    response = http_get(uri, ctx)

    if response.status_code not in (200, 404):
        ctx.obj.handler.set_message(f"Fetching the settings failed with {response.status_code}")
        ctx.obj.handler.set_failed()
        exit_cli(ctx, 1)

    if response.status_code == 404:
        return {}

    try:
        return response.json()
    except json.JSONDecodeError as e:
        ctx.obj.logger.error(f"An exception ocurred while decoding upstream JSON:  {e}")
        ctx.obj.handler.set_message("A valid JSON-file could not be obtained from upstream")
        ctx.obj.handler.set_failed()
        exit_cli(ctx, 1)


def print_output(output: dict | list, stderr: bool = False) -> None:
    """Pretty-print a dictionary or list as formatted JSON to stdout.

    Args:
        output: The dictionary or list to be printed.
        stderr: Print output to standard error instead of stdout.
    """
    click.echo(json.dumps(output, indent=4), err=stderr)


def validate_simple_import(
    ctx: click.Context, settings: list[dict], upstream_settings: list[dict], replace: bool
) -> None:
    """Validates metadata import by checking the structure and presence of metadata entries.

    This function ensures that the provided `settings` is a list and checks if the metadata
    is already present in `upstream_settings`. If `replace` is True, it verifies if the
    metadata is identical. If not, it checks if all entries in `settings` are already present.

    Args:
        ctx: click Context object
        settings: List of dictionaries representing the metadata entries to validate.
        upstream_settings: List of dictionaries representing existing upstream metadata entries.
        replace: If True, checks if the metadata is identical for replacement.
                 If False, checks if all entries are already present.

    Raises:
        SystemExit: Exits with code 1 if `settings` is not a list.
                   Exits with code 0 if metadata is already present.
    """
    if not isinstance(settings, list):
        ctx.obj.handler.set_message("Data must be provided as a list")
        ctx.obj.handler.set_failed()
        exit_cli(ctx, 1)
    if replace and upstream_settings == settings:
        ctx.obj.handler.set_message("Requested data is already present")
        ctx.obj.handler.set_success()
        exit_cli(ctx, 0)
    if not replace and all(item in upstream_settings for item in settings):
        ctx.obj.handler.set_message("Requested data is already present")
        ctx.obj.handler.set_success()
        exit_cli(ctx, 0)


def handle_import_early_exit(ctx: click.Context, message: str, ignore_errors: bool) -> None:
    """
    Handle import errors with configurable behavior based on ignore_errors flag.

    When ignore_errors is False (strict mode):
    - Prints error to stdout and exits immediately with code 1
    - Stops all further processing

    When ignore_errors is True (permissive mode):
    - Logs error but continues execution
    - Allows processing of remaining items

    Args:
        ctx: Click context object
        message: Dictionary containing error information (typically with 'error' key)
        ignore_errors: If True, log error and continue; if False, log error and exit
    """
    if ignore_errors:
        ctx.obj.logger.error(message)
    else:
        ctx.obj.handler.set_message(message)
        ctx.obj.handler.set_failed()
        exit_cli(ctx)
