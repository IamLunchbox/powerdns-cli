"""Utilities library for the main cli functions"""

import json
from typing import Any, NoReturn, TextIO

import click
import requests


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
    message: str,
    response: requests.Response = None,
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
        message: Mmessage to set in the handler.
        response: HTTP response object.
        print_data: If True, sets the response data in the handler.
    """
    ctx.obj.handler.set_message(message)
    if response:
        ctx.obj.handler.set_data(response)
    # pass response to set success as well to enable the handler to set debug data from the response
    # body
    ctx.obj.handler.set_success(success, response)
    exit_cli(ctx, print_data=print_data)


def http_delete(uri: str, ctx: click.Context, params: dict = None) -> requests.Response:
    """HTTP DELETE request"""
    try:
        request = ctx.obj.session.delete(uri, params=params, timeout=10)
        ctx.obj.handler.log_http_data(ctx, request)
        return request
    except requests.RequestException as e:
        exit_action(ctx, False, f"Request error: {e}.")


def http_get(
    uri: str, ctx: click.Context, params: dict = None, log_body: bool = True
) -> requests.Response:
    """HTTP GET request"""
    try:
        request = ctx.obj.session.get(uri, params=params, timeout=10)
        ctx.obj.handler.log_http_data(ctx, request, log_body)
        return request
    except requests.RequestException as e:
        exit_action(ctx, False, f"Request error: {e}.")


def http_patch(
    uri: str, ctx: click.Context, payload: dict, log_body: bool = True
) -> requests.Response:
    """HTTP PATCH request"""
    try:
        request = ctx.obj.session.patch(uri, json=payload, timeout=10)
        ctx.obj.handler.log_http_data(ctx, request, log_body)
        return request
    except requests.RequestException as e:
        exit_action(ctx, False, f"Request error: {e}.")


def http_post(
    uri: str, ctx: click.Context, payload: dict, log_body: bool = True
) -> requests.Response:
    """HTTP POST request"""
    try:
        request = ctx.obj.session.post(uri, json=payload, timeout=10)
        ctx.obj.handler.log_http_data(ctx, request, log_body)
        return request
    except requests.RequestException as e:
        exit_action(ctx, False, f"Request error: {e}.")


def http_put(
    uri: str, ctx: click.Context, payload: dict = None, params: dict = None, log_body: bool = True
) -> requests.Response:
    """HTTP PUT request"""
    try:
        request = ctx.obj.session.put(uri, json=payload, params=params, timeout=10)
        ctx.obj.handler.log_http_data(ctx, request, log_body)
        return request
    except requests.RequestException as e:
        exit_action(ctx, False, f"Request error: {e}.")


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


def extract_file(ctx: click.Context, input_file: TextIO) -> dict | list:
    """Extracts a json object from a file input and returns it."""
    try:
        return_object = json.load(input_file)
    except (json.JSONDecodeError, ValueError, TypeError) as e:
        ctx.obj.logger.error(f"Failed loading the file with {e}.")
        exit_action(ctx, False, f"Failed loading the file with {e}.")
    if not isinstance(return_object, (dict, list)):
        ctx.obj.logger.error("Failed loading the file due to an unexpected filetype.")
        exit_action(ctx, False, "Failed loading the file due to an unexpected filetype.")
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
        ctx.obj.handler.set_message("Fetching the settings failed.")
        ctx.obj.handler.set_success(False)
        exit_cli(ctx)

    if response.status_code == 404:
        return {}

    try:
        return response.json()
    except json.JSONDecodeError as e:
        ctx.obj.logger.error(f"An exception ocurred while decoding upstream JSON:  {e}.")
        ctx.obj.handler.set_message("A valid JSON-file could not be obtained from upstream.")
        ctx.obj.handler.set_success(False)
        exit_cli(ctx)


def validate_simple_import(
    ctx: click.Context, settings: list[dict], upstream_settings: list[dict], replace: bool
) -> None:
    """Validates metadata import by checking the structure and presence of entries.

    This function ensures that the provided `settings` is a list and checks if the data
    is already present in `upstream_settings`. If `replace` is True, it verifies if the
    data is identical. If not, it checks if all entries in `settings` are already present.

    Args:
        ctx: click Context object
        settings: List of dictionaries representing the data entries to validate.
        upstream_settings: List of dictionaries representing existing upstream data entries.
        replace: If True, checks if the data is identical for replacement.
                 If False, checks if all entries are already present.

    Raises:
        SystemExit: Exits with code 1 if `settings` is not a list.
                   Exits with code 0 if data is already present.
    """
    if not isinstance(settings, list):
        ctx.obj.handler.set_message("Data must be provided as a list.")
        ctx.obj.handler.set_failed()
        exit_cli(ctx)
    if replace and upstream_settings == settings:
        ctx.obj.handler.set_message("Requested data is already present.")
        ctx.obj.handler.set_success()
        exit_cli(ctx)
    if not replace and all(item in upstream_settings for item in settings):
        ctx.obj.handler.set_message("Requested data is already present.")
        ctx.obj.handler.set_success()
        exit_cli(ctx)


def show_setting(
    ctx: Any,
    uri: str,
    setting_name: str,
    action: str,
) -> NoReturn:
    """
    Perform an HTTP GET request to the specified URI and log the result.

    Args:
        ctx: Context object containing logger and other utilities.
        uri: The URI to send the GET request to.
        setting_name: The name of the setting being acted upon.
        action: The action performed (e.g., "update", "fetch").

    Raises:
        SystemExit: Exits with code 1 GET request is not answered with 200.
                   Exits with code 0 if `action` was successfull.
    """
    r = http_get(uri, ctx)
    if r.status_code == 200:
        ctx.obj.logger.info(f"Successfully {action}ed {setting_name}.")
        exit_action(
            ctx,
            success=True,
            message=f"Successfully {action}ed {setting_name}.",
            response=r,
            print_data=True,
        )
    elif r.status_code == 404:
        ctx.obj.logger.warning(f"Failed {action}ing, {setting_name} not found.")
        exit_action(
            ctx,
            success=False,
            response=r,
            message=f"Failed {action}ing, {setting_name} not found.",
        )
    else:
        ctx.obj.logger.error(f"Failed {action}ing {setting_name}.")
        exit_action(
            ctx,
            success=False,
            message=f"Failed {action}ing {setting_name} with status code.",
            response=r,
        )


def is_id_or_name_present(ctx: click.Context, dict_to_check: dict[str, str]) -> None:
    """
    Validates whether either 'id' or 'name' is present in the provided dictionary.

    Args:
        ctx: Click context object, used for logging and exiting the CLI.
        dict_to_check: Dictionary containing 'id' or 'name' keys to validate.

    Raises:
        SystemExit: Exits the CLI with a failure status if neither 'id' nor 'name' is present.
    """
    if not dict_to_check.get("id") and not dict_to_check.get("name"):
        ctx.obj.logger.error("Either 'name' or 'id' must be present to determine the zone.")
        exit_action(
            ctx,
            success=False,
            message="Either 'name' or 'id' must be present to determine the zone.",
        )
