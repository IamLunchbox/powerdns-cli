"""Utilities library for the main cli functions"""

import json
from typing import TextIO

import click
import requests


def is_autoprimary_present(uri: str, ctx: click.Context, ip: str, nameserver: str) -> bool:
    """Checks if the ip and nameserver are already in the autoprimary list"""
    upstream_autoprimaries = http_get(uri, ctx)
    if upstream_autoprimaries.status_code == 200:
        autoprimares = upstream_autoprimaries.json()
        for autoprimary in autoprimares:
            if (
                autoprimary.get("nameserver", None) == nameserver
                and autoprimary.get("ip", None) == ip
            ):
                return True
    return False


def confirm(message: str, force: bool) -> None:
    """Confirmation function to keep users from doing potentially dangerous actions.
    Uses the force flag to determine if a manual confirmation is required."""
    if not force:
        click.echo(message)
        confirmation = input()
        if confirmation not in ("y", "Y", "YES", "yes", "Yes"):
            click.echo("Aborting")
            raise SystemExit(1)


def does_cryptokey_exist(
    uri: str, exit_message: str, exit_code: int, ctx: click.Context
) -> requests.Response:
    """Checks if the provided dns cryptokey is already existing in the backend"""
    r = http_get(uri, ctx)
    if r.status_code == 404:
        click.echo(json.dumps({"message": exit_message}))
        raise SystemExit(exit_code)
    return r


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
        click.echo(json.dumps(optional_json))
        return True
    if content.status_code in exp_status_code:
        click.echo(json.dumps(content.json()))
        return True
    if content.headers.get("Content-Type", "").startswith("text/plain"):
        click.echo(json.dumps({"error": content.text}))
        return False
    # Catch unexpected empty responses
    try:
        click.echo(json.dumps(content.json()))
    except json.JSONDecodeError:
        click.echo(
            json.dumps(
                {"error": f"Non json response from server with status {content.status_code}"},
                indent=4
            )
        )
    return False


def http_delete(uri: str, ctx: click.Context, params: dict = None) -> requests.Response:
    """HTTP DELETE request"""
    try:
        request = ctx.obj["session"].delete(uri, params=params, timeout=10)
        return request
    except requests.RequestException as e:
        raise SystemExit(json.dumps({"error": f"Request error: {e}"}, indent=4)) from e


def http_get(uri: str, ctx: click.Context, params: dict = None) -> requests.Response:
    """HTTP GET request"""
    try:
        request = ctx.obj["session"].get(uri, params=params, timeout=10)
        return request
    except requests.RequestException as e:
        raise SystemExit(json.dumps({"error": f"Request error: {e}"}, indent=4)) from e


def http_patch(uri: str, ctx: click.Context, payload: dict) -> requests.Response:
    """HTTP PATCH request"""
    try:
        request = ctx.obj["session"].patch(uri, json=payload, timeout=10)
        return request
    except requests.RequestException as e:
        raise SystemExit(json.dumps({"error": f"Request error: {e}"}, indent=4)) from e


def http_post(uri: str, ctx: click.Context, payload: dict) -> requests.Response:
    """HTTP POST request"""
    try:
        request = ctx.obj["session"].post(uri, json=payload, timeout=10)
        return request
    except requests.RequestException as e:
        raise SystemExit(json.dumps({"error": f"Request error: {e}"}, indent=4)) from e


def http_put(
    uri: str, ctx: click.Context, payload: dict = None, params: dict = None
) -> requests.Response:
    """HTTP PUT request"""
    try:
        request = ctx.obj["session"].put(uri, json=payload, params=params, timeout=10)
        return request
    except requests.RequestException as e:
        raise SystemExit(json.dumps({"error": f"Request error: {e}"}, indent=4)) from e


def query_zones(ctx) -> list:
    """Returns all zones of the dns server"""
    r = http_get(f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones", ctx)
    if r.status_code != 200:
        click.echo(json.dumps({"error": r.json()}))
        raise SystemExit(1)
    return r.json()


def query_zone_rrsets(uri: str, ctx) -> list[dict]:
    """Queries the configuration of the given zone and returns a list of all RRSETs"""
    r = http_get(uri, ctx)
    if r.status_code != 200:
        click.echo(json.dumps(r.json()))
        raise SystemExit(1)
    return r.json()["rrsets"]


def lowercase_secret(secret: str) -> str:
    """Splits the private key of a dnssec into the secret and metadata part and lowercases the
    metadata for comparison purposes"""
    last_colon_index = secret.rfind(":")
    before_last_colon = secret[:last_colon_index]
    after_last_colon = secret[last_colon_index:]
    return before_last_colon.lower() + after_last_colon


def make_dnsname(name: str, zone: str) -> str:
    """Returns either the combination or zone or just a zone when @ is provided as name"""
    if name == "@":
        return zone
    return f"{name}.{zone}"


def is_dnssec_key_present(uri: str, secret: str, ctx: click.Context) -> bool:
    """Retrieves all private keys for the given zone and checks if the private key is corresponding
    to the private key provided by the user"""
    # Powerdns will accept secrets without trailing newlines and actually appends one by itself -
    # and it will fix upper/lowercase in non-secret data
    secret = secret.rstrip("\n")
    secret = lowercase_secret(secret)
    present_keys = http_get(uri, ctx)
    return any(
        secret
        == lowercase_secret(http_get(f"{uri}/{key['id']}", ctx).json()["privatekey"].rstrip("\n"))
        for key in present_keys.json()
    )


def is_metadata_content_present(uri: str, ctx: click.Context, new_data: dict) -> bool:
    """Checks if an entry is already existing in the metadata for the zone. Will not check
    for identical entries, only if the given metadata information is in the corresponding list
    """
    zone_metadata = http_get(uri, ctx)
    if zone_metadata.status_code != 200:
        return False
    if (
        new_data["kind"] == zone_metadata.json()["kind"]
        and new_data["metadata"][0] in zone_metadata.json()["metadata"]
    ):
        return True
    return False


def is_metadata_content_identical(uri: str, ctx: click.Context, new_data: dict) -> bool:
    """Checks if the metadata entry is identical to the new content"""
    zone_metadata = http_get(uri, ctx)
    if zone_metadata.status_code != 200:
        return False
    if new_data == zone_metadata.json():
        return True
    return False


def is_metadata_entry_present(uri: str, ctx: click.Context) -> bool:
    """Checks if a metadata entry exists at all"""
    zone_metadata = http_get(uri, ctx)
    # When there is no metadata set of the given type, the api will still
    # return 200 and a dict with an emtpy list of metadata entries
    if zone_metadata.status_code == 200 and zone_metadata.json()["metadata"]:
        return True
    return False


def is_matching_rrset_present(uri: str, ctx: click.Context, new_rrset: dict) -> dict:
    """Checks if a RRSETs is already existing in the dns database, does not check records"""
    zone_rrsets = query_zone_rrsets(uri, ctx)
    for upstream_rrset in zone_rrsets:
        if all(upstream_rrset[key] == new_rrset[key] for key in ("name", "type")):
            return upstream_rrset
    return {}


def is_content_present(uri: str, ctx: click.Context, new_rrset: dict) -> bool:
    """Checks if a matching rrset is present and if the new record is also already present"""
    zone_rrsets = query_zone_rrsets(uri, ctx)
    for rrset in zone_rrsets:
        if (
            # Check if general entry name, type and ttl are the same
            all(rrset[key] == new_rrset[key] for key in ("name", "type", "ttl"))
            and
            # Check if all references within that rrset are identical
            all(record in rrset["records"] for record in new_rrset["records"])
        ):
            return True
    return False


def merge_rrsets(uri: str, ctx: click.Context, new_rrset: dict) -> list:
    """Merge the upstream and local rrset records to create a unified and deduplicated set"""
    zone_rrsets = query_zone_rrsets(uri, ctx)
    merged_rrsets = new_rrset["records"].copy()
    for upstream_rrset in zone_rrsets:
        if all(upstream_rrset[key] == new_rrset[key] for key in ("name", "type")):
            merged_rrsets.extend(
                [
                    record
                    for record in upstream_rrset["records"]
                    if record["content"] != new_rrset["records"][0]["content"]
                ]
            )
    return merged_rrsets


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
        click.echo(json.dumps({"error": f"Loading the file failed with {e}"}, indent=4))
        raise SystemExit(1) from e
    if not isinstance(return_object, (dict, list)):
        raise ValueError("utils.extract file returned an unexpected filetype")
    return return_object


def read_settings_from_upstream(
    uri: str, ctx: click.Context, nested_key: str | None = None
) -> dict:
    """Fetch settings from upstream URI with optional nested key extraction.

    Args:
        uri: Endpoint URL to fetch settings from
        ctx: Click context for HTTP requests
        nested_key: Optional dot-notation key path to extract (e.g., "parent.child")

    Returns:
        Dictionary of settings or specific nested value if key was provided
        Empty dict if request fails or parsing fails

    Raises:
        SystemExit: When nested_key doesn't exist in response
    """
    response = http_get(uri, ctx)

    if response.status_code != 200:
        return {}

    try:
        data = response.json()
        return data.get(nested_key) if nested_key else data
    except KeyError as e:
        click.echo(
            json.dumps(
                {"error": f"Requested key does not exist: {e}", "available_keys": list(data.keys())}
            )
        )
        raise SystemExit(1) from e


def import_setting(
    uri: str,
    ctx: click.Context,
    new_settings: dict | list,
    replace: bool = False,
    merge: bool = False,
) -> dict | list:
    """Passes the given dictionary or list to the specified URI.

    Args:
        uri: The endpoint to send the settings to.
        ctx: Context object for HTTP requests.
        new_settings: The new settings to import (dict or list).
        replace: If True, replace existing settings.

    Returns:
        dict | list: The updated settings.

    Raises:
        SystemExit: If settings already exist and neither merge nor replace is requested,
                   or if the nested key does not exist.
    """
    upstream_settings = read_settings_from_upstream(uri, ctx)
    # Check for conflicts or early exit
    if upstream_settings:
        if not any((replace, merge)):
            click.echo(
                json.dumps({"message": "Setting already present, refusing to replace"}, indent=4)
            )
            raise SystemExit(0)

        if new_settings == upstream_settings or (
            not replace
            and (isinstance(upstream_settings, list) and new_settings in upstream_settings)
        ):
            click.echo(json.dumps({"message": "Your setting is already present"}, indent=4))
            raise SystemExit(0)

    # Prepare payload
    if replace or not upstream_settings:
        payload = new_settings
    else:
        payload = upstream_settings.copy()  # Avoid modifying the original upstream_settings
        if isinstance(payload, list):
            # as of now no endpoint does support uploading lists but rather
            # extends an existing list upstream
            # until a later endpoint requires it, list items will just result
            # in a single item being uploaded
            payload = new_settings
        elif isinstance(payload, dict):
            payload.update(new_settings)

    return payload


def send_settings_update(
    uri: str, ctx: click.Context, payload: dict | list, method: str
) -> requests.Response:
    """Sends settings update using the specified HTTP method.

    Args:
        uri: The endpoint to send the request to.
        ctx: Context object for HTTP requests.
        payload: The data to send.
        method: HTTP method to use ('post', 'put', or 'patch').

    Returns:
        requests.Response: The HTTP response from the server.

    Raises:
        ValueError: If an unsupported HTTP method is provided.
    """
    method_handlers = {"post": http_post, "put": http_put, "patch": http_patch}

    if handler := method_handlers.get(method.lower()):
        return handler(uri, ctx, payload=payload)

    raise ValueError(f"Unsupported method: {method}")
