"""Utilities library for the main cli functions"""

import json
from typing import TextIO

import click
import requests


def is_autoprimary_present(uri: str, ctx: click.Context, ip: str, nameserver: str) -> bool:
    """Checks if the specified IP and nameserver are already present in the autoprimary list.

    This function sends a GET request to the provided `uri` to fetch the current list of
    autoprimary entries. It then checks if any entry matches the provided `ip` and `nameserver`.
    Returns `True` if a match is found, otherwise returns `False`.

    Args:
        uri (str): The URI to fetch the autoprimary list.
        ctx (click.Context): Click context object for command-line operations.
        ip (str): The IP address to check for in the autoprimary list.
        nameserver (str): The nameserver to check for in the autoprimary list.

    Returns:
        bool: `True` if the IP and nameserver are found in the autoprimary list, otherwise `False`.
    """
    upstream_autoprimaries = http_get(uri, ctx)
    if upstream_autoprimaries.status_code == 200:
        autoprimaries = upstream_autoprimaries.json()
        for autoprimary in autoprimaries:
            if autoprimary.get("nameserver") == nameserver and autoprimary.get("ip") == ip:
                return True
    return False


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


def does_cryptokey_exist(
    uri: str, exit_message: str, exit_code: int, ctx: click.Context
) -> requests.Response:
    """Checks if the DNS cryptokey already exists in the backend.

    Sends a GET request to the provided `uri` to check for the existence of a DNS cryptokey.
    If the response status code is 404, it prints the provided `exit_message` and exits
    with the specified `exit_code`. Otherwise, it returns the response object.

    Args:
        uri (str): The URI to check for the DNS cryptokey.
        exit_message (str): The message to display if the cryptokey does not exist.
        exit_code (int): The exit code to use if the cryptokey does not exist.
        ctx (click.Context): Click context object for command-line operations.

    Returns:
        requests.Response: The HTTP response object if the cryptokey exists.

    Raises:
        SystemExit: If the cryptokey does not exist (HTTP 404 response).
    """
    r = http_get(uri, ctx)
    if r.status_code == 404:
        print_output({"message": exit_message})
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
        print_output({"error": f"Non json response from server with status {content.status_code}"})
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


def query_zones(ctx: click.Context) -> list:
    """Fetches and returns all zones configured on the DNS server.

    Sends a GET request to the DNS server's API endpoint to retrieve the list of zones.
    If the request fails (non-200 status code), it prints the error and exits with a status code 1.
    Otherwise, it returns the list of zones as parsed JSON.

    Args:
        ctx (click.Context): Click context object containing the API host and other configuration.

    Returns:
        list: A list of zones configured on the DNS server, parsed from the JSON response.

    Raises:
        SystemExit: If the request to fetch zones fails (non-200 status code).
    """
    r = http_get(f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones", ctx)
    if r.status_code != 200:
        print_output({"error": r.json()})
        raise SystemExit(1)
    return r.json()


def query_zone_rrsets(uri: str, ctx) -> list[dict]:
    """Queries the configuration of the given zone and returns a list of all RRSETs.

    Sends a GET request to the specified `uri` to fetch the zone's RRSETs.
    If response status is not 200, it prints the error response and exits with a status code of 1.
    Otherwise, it returns the list of RRSETs from the JSON response.

    Args:
        uri (str): The URI to query for the zone's RRSETs.
        ctx (click.Context): Click context object for command-line operations.

    Returns:
        list[dict]: A list of dictionaries, where each dictionary represents an RRSET.

    Raises:
        SystemExit: If the request to fetch RRSETs fails (non-200 status code).
    """
    r = http_get(uri, ctx)
    if r.status_code != 200:
        print_output(r.json())
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
        Dictionary or list of settings or specific nested value if key was provided
        Empty dict if request fails or parsing fails

    Raises:
        SystemExit: When nested_key doesn't exist in response
    """
    response = http_get(uri, ctx)

    if response.status_code != 200:
        return {}

    try:
        data = response.json()
        return data
    except KeyError as e:
        print_output(
            {"error": f"Requested key does not exist: {e}", "available_keys": list(data.keys())}
        )
        raise SystemExit(1) from e


def import_cryptokey_pubkeys(
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
            print_output({"message": "Setting already present, refusing to replace"})
            raise SystemExit(0)

        if new_settings == upstream_settings or (
            not replace
            and (isinstance(upstream_settings, list) and new_settings in upstream_settings)
        ):
            print_output({"message": "Your setting is already present"})
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


def is_zone_in_view(new_view: dict, upstream: list[dict]) -> bool:
    """Check if all zones in a new view are present in an upstream view of the same name.

    Args:
        new_view: Dictionary with 'name' and 'views' (set or list of zones).
        upstream: List of dictionaries, each with 'name' and 'views' (set or list of zones).

    Returns:
        bool: True if an upstream view with the same name contains all zones, False otherwise.
    """
    return any(
        upstream_view["name"] == new_view["name"]
        and all(item in upstream_view["views"] for item in new_view["views"])
        for upstream_view in upstream
    )


def validate_view_import(settings: list) -> bool:
    """Validate the structure of view import settings.

    Args:
        settings: A list of dictionaries, each with a single key-value pair.
                 The value should be a list of views.

    Returns:
        bool: True if all items are valid, False otherwise.
    """
    if not isinstance(settings, list):
        return False

    for item in settings:
        if not isinstance(item, dict) or len(item) != 1:
            return False
        value = next(iter(item.values()))
        if not isinstance(value, list):
            return False

    return True


def reformat_view_imports(local_views: list, uri: str, ctx) -> tuple[list[dict], list[dict]]:
    """Reformat local and upstream view settings for comparison.

    Args:
        local_views: List of local view configurations.
        uri: Base URI for upstream API requests.
        ctx: Click context for HTTP requests.

    Returns:
        A tuple of two lists: restructured local settings and upstream settings.
        Each list contains dictionaries with 'name' and 'views' (as sets).
    """
    restructured_settings = [
        {
            "name": next(iter(item.keys())),
            "views": {make_canonical(view) for view in next(iter(item.values()))},
        }
        for item in local_views
    ]

    upstream_views = read_settings_from_upstream(uri, ctx)["views"]
    upstream_settings = [
        {
            "name": key,
            "views": set(read_settings_from_upstream(f"{uri}/{key}", ctx)["zones"]),
        }
        for key in upstream_views
    ]

    return restructured_settings, upstream_settings


def add_views(
    views_to_add: list[dict],
    uri: str,
    ctx: click.Context,
    continue_on_error: bool = False,
) -> None:
    """Add views to a specified URI, handling errors according to the continue_on_error flag.

    Args:
        views_to_add: List of dictionaries, each containing 'name' and 'view' keys.
        uri: Base URI for the POST requests.
        ctx: Click context for HTTP requests.
        continue_on_error: If True, log warnings and continue on error; otherwise, abort.

    Raises:
        SystemExit: If continue_on_error is False and a request fails.
    """
    for item in views_to_add:
        name, view = item["name"], item["view"]
        r = http_post(f"{uri}/{name}", ctx, payload={"name": view})

        if r.status_code != 204:
            handle_import_early_exit(
                {
                    "error": f"Failed to add view '{view}' to '{name}' "
                    f"(status: {r.status_code}, body: '{r.text}')"
                },
                continue_on_error,
            )


def delete_views(
    views_to_delete: list[dict],
    uri: str,
    ctx: click.Context,
    continue_on_error: bool = False,
) -> None:
    """Delete views from a specified URI, handling errors according to the abort_on_error flag.

    Args:
        views_to_delete: List of dictionaries, each containing 'name' and 'view' keys.
        uri: Base URI for the delete requests.
        ctx: Click context for HTTP requests.
        continue_on_error: If False, abort on the first error; otherwise, log warnings and continue.

    Raises:
        SystemExit: If continue_on_error is True and a request fails.
    """
    for item in views_to_delete:
        name, view = item["name"], item["view"]
        r = http_delete(f"{uri}/{name}/{view}", ctx)

        if r.status_code != 204:
            handle_import_early_exit(
                {
                    "error": f"Failed to delete view '{view}' from '{name}' "
                    f"(status: {r.status_code}, body: '{r.text}')"
                },
                continue_on_error,
            )


def print_output(output: dict | list, stderr: bool = False) -> None:
    """Pretty-print a dictionary or list as formatted JSON to stdout.

    Args:
        output: The dictionary or list to be printed.
        stderr: Print output to standard error instead of stdout.
    """
    click.echo(json.dumps(output, indent=4), err=stderr)


def replace_metadata_from_import(
    uri: str,
    ctx: click.Context,
    upstream_settings: list,
    settings: list,
    continue_on_error: bool = False,
) -> None:
    """Replaces metadata entries from an import, handling additions and deletions as needed.

    This function compares upstream settings with the provided settings list, adds new entries,
    and deletes obsolete ones. It aborts on errors unless `continue_on_error` is True.

    Args:
        uri: The base URI for API requests.
        ctx: Click context object for command-line operations.
        upstream_settings: List of dictionaries representing existing upstream metadata entries.
        settings: List of dictionaries representing desired metadata entries.
        continue_on_error: If True, continues execution after errors instead of aborting.
                           Defaults to False.

    Raises:
        SystemExit: If an error occurs during addition or deletion of metadata entries,
                   unless `continue_on_error` is True.
    """
    existing_upstreams = []
    upstreams_to_delete = []
    for metadata_entry in upstream_settings:
        if metadata_entry["kind"] == "SOA_EDIT_API":
            continue
        if metadata_entry in settings:
            existing_upstreams.append(metadata_entry)
        else:
            upstreams_to_delete.append(metadata_entry)
    for metadata_entry in settings:
        if metadata_entry not in existing_upstreams:
            r = http_post(uri, ctx, payload=metadata_entry)
            if not r.status_code == 201:
                handle_import_early_exit(
                    {
                        "error": f"Failed adding {metadata_entry['kind']} with status "
                        f"{r.status_code} and body {r.text}"
                    },
                    continue_on_error,
                )
    for metadata_entry in upstreams_to_delete:
        r = http_delete(f"{uri}/{metadata_entry['kind']}", ctx)
        if r.status_code != 204:
            handle_import_early_exit(
                {
                    "error": f"Failed deleting tsigkey {metadata_entry['kind']} with "
                    f"status {r.status_code} and body {r.text}"
                },
                continue_on_error,
            )


def add_metadata_from_import(
    uri: str,
    ctx: click.Context,
    upstream_settings: list,
    settings: list,
    continue_on_error: bool = False,
) -> None:
    """Adds metadata entries from an import, updating existing entries if necessary.

    This function iterates through the provided settings, checks for existing metadata entries
    in `upstream_settings`, and either updates or adds them via an API call. If an error occurs,
    it aborts unless `continue_on_error` is True.

    Args:
        uri: The base URI for API requests.
        ctx: Click context object for command-line operations.
        upstream_settings: List of dictionaries representing existing upstream metadata entries.
        settings: List of dictionaries representing desired metadata entries to add or update.
        continue_on_error: If True, continues execution after errors instead of aborting.
                           Defaults to False.

    Raises:
        SystemExit: If an error occurs during the addition or update of metadata entries,
                   unless `continue_on_error` is True.
    """
    for metadata_entry in settings:
        if metadata_entry["kind"] == "SOA-EDIT-API":
            continue
        payload = None
        for existing_metadata in upstream_settings:
            if metadata_entry["kind"] == existing_metadata["kind"]:
                payload = existing_metadata.copy()
                payload.update(metadata_entry)
        if not payload:
            payload = metadata_entry.copy()
        r = http_post(uri, ctx, payload=payload)
        if r.status_code != 201:
            handle_import_early_exit(
                {
                    "error": f"Failed adding metadata {payload['kind']}, "
                    "aborting further configuration changes"
                },
                continue_on_error,
            )


def validate_simple_import(
    settings: list[dict], upstream_settings: list[dict], replace: bool
) -> None:
    """Validates metadata import by checking the structure and presence of metadata entries.

    This function ensures that the provided `settings` is a list and checks if the metadata
    is already present in `upstream_settings`. If `replace` is True, it verifies if the
    metadata is identical. If not, it checks if all entries in `settings` are already present.

    Args:
        settings: List of dictionaries representing the metadata entries to validate.
        upstream_settings: List of dictionaries representing existing upstream metadata entries.
        replace: If True, checks if the metadata is identical for replacement.
                 If False, checks if all entries are already present.

    Raises:
        SystemExit: Exits with code 1 if `settings` is not a list.
                   Exits with code 0 if metadata is already present.
    """
    if not isinstance(settings, list):
        print_output({"error": "Data must be provided as a list"})
        raise SystemExit(1)
    if replace and upstream_settings == settings:
        print_output({"message": "Requested data is already present"})
        raise SystemExit(0)
    if not replace and all(item in upstream_settings for item in settings):
        print_output({"message": "Requested data is already present"})
        raise SystemExit(0)


def replace_autoprimary_import(
    uri, ctx, settings: list[dict], upstream_settings: list[dict], ignore_errors: bool
) -> None:
    """Replaces nameserver configurations by adding new entries and removing obsolete ones.

    This function compares the provided `settings` with `upstream_settings` to determine which
    nameserver configurations to add or delete. It sends POST requests to add new nameservers
    and DELETE requests to remove obsolete ones. If an error occurs, it either logs the error
    and continues (if `ignore_errors` is True) or aborts the process.

    Args:
        uri (str): The base URI for API requests.
        ctx (click.Context): Click context object for command-line operations.
        settings (List[Dict]): List of dictionaries representing desired nameserver configurations.
        upstream_settings (List[Dict]): List of dictionaries representing upstream configurations.
        ignore_errors (bool): If True, continues execution after errors instead of aborting.

    Raises:
        SystemExit: If an error occurs during the addition or deletion of a nameserver configuration
                   and `ignore_errors` is False.
    """
    existing_upstreams = []
    upstreams_to_delete = []
    for nameserver in upstream_settings:
        if nameserver in settings:
            existing_upstreams.append(nameserver)
        else:
            upstreams_to_delete.append(nameserver)
    for nameserver in settings:
        if nameserver not in existing_upstreams:
            r = http_post(uri, ctx, payload=nameserver)
            if r.status_code != 201:
                handle_import_early_exit(
                    {"error": f"Failed adding nameserver {nameserver}"}, ignore_errors
                )
    for nameserver in upstreams_to_delete:
        r = http_delete(f"{uri}/{nameserver['nameserver']}/{nameserver['ip']}", ctx)
        if not r.status_code == 204:
            handle_import_early_exit(
                {"error": f"Failed deleting nameserver {nameserver}"}, ignore_errors
            )


def replace_network_import(
    uri, ctx, settings: list[dict], upstream_settings: list[dict], ignore_errors: bool
) -> None:
    """Replaces network configurations by adding new entries and removing obsolete ones.

    This function compares the provided `settings` with `upstream_settings` to determine which
    network configurations to add or delete. It sends PUT requests to update or remove network
    configurations as needed. If an error occurs, it either logs the error and continues
    (if `ignore_errors` is True) or aborts the process.

    Args:
        uri (str): The base URI for API requests.
        ctx (click.Context): Click context object for command-line operations.
        settings (List[Dict]): List of dictionaries representing desired network configurations.
        upstream_settings (List[Dict]): List of dictionaries representing upstream configurations.
        ignore_errors (bool): If True, continues execution after errors instead of aborting.

    Raises:
        SystemExit: If an error occurs during the addition or deletion of a network configuration
                   and `ignore_errors` is False.
    """
    existing_upstreams = []
    upstreams_to_delete = []
    for network_item in upstream_settings:
        if network_item in settings:
            existing_upstreams.append(network_item)
        else:
            upstreams_to_delete.append(network_item)
    for network_item in settings:
        if network_item not in existing_upstreams:
            r = http_put(
                f"{uri}/{network_item['network']}", ctx, payload={"view": network_item["view"]}
            )
            if r.status_code != 201:
                handle_import_early_exit(
                    {
                        "error": f"Failed adding network {network_item['network']} "
                        f"to new {network_item['view']} with status {r.status_code} "
                        f"and body {r.text}"
                    },
                    ignore_errors,
                )
    for network_item in upstreams_to_delete:
        r = http_put(f"{uri}/{network_item['network']}", ctx, payload={"view": ""})
        if r.status_code != 204:
            handle_import_early_exit(
                {
                    "error": f"Failed adding network {network_item['network']} from new "
                    f"{network_item['view']} with status {r.status_code} and body "
                    f"{r.text}"
                },
                ignore_errors,
            )


def add_network_import(uri: str, ctx: click.Context, settings: list, ignore_errors: bool) -> None:
    """Adds network configurations from an import using HTTP PUT requests.

    This function iterates through the provided `settings` and sends a PUT request
    for each network item to the specified URI. If the request fails, it either
    logs the error and continues (if `ignore_errors` is True) or aborts the process.

    Args:
        uri: The base URI for API requests.
        ctx: Click context object for command-line operations.
        settings: List of dictionaries representing network configurations to add.
        ignore_errors: If True, continues execution after errors instead of aborting.

    Raises:
        SystemExit: If an error occurs during the addition of a network configuration
                   and `ignore_errors` is False.
    """
    for network_item in settings:
        r = http_put(
            f"{uri}/{network_item['network']}", ctx, payload={"view": network_item["view"]}
        )
        if r.status_code != 204:
            handle_import_early_exit(
                {
                    "error": f"Failed adding network {network_item['network']} from new "
                    f"{network_item['view']} with status {r.status_code} and body "
                    f"{r.text}"
                },
                ignore_errors,
            )


def update_zone_data(
    uri: str, ctx: click.Context, upstream_settings: list, setting_names: list
) -> None:
    """
    Update upstream zone settings with detailed zone data from the API.

    For each upstream zone that exists in the setting_names, fetches the complete
    zone configuration from the API and updates the upstream_settings in place.
    This is typically used to enrich basic zone listings with full configuration data.

    Args:
        uri: Base API endpoint URI for zones
        ctx: Click context object containing authentication and configuration
        upstream_settings: List of upstream zone configurations to update in place
        setting_names: Set of zone names that should be updated

    Raises:
        SystemExit: If any API call fails or returns invalid data
    """
    for upstream_zone in upstream_settings:
        if upstream_zone["name"] in setting_names:
            r = http_get(f"{uri}/{upstream_zone['name']}", ctx)
            if r.status_code == 200:
                upstream_zone.update(r.json())
            else:
                print_output(
                    {
                        "error": "Obtaining zone information failed with status "
                        f"{r.status_code} and text {r.text}"
                    },
                )
                raise SystemExit(1)


def replace_rrset_import(
    uri: str,
    ctx: click.Context,
    settings: list,
    upstream_settings: list,
    setting_names: list,
    ignore_errors: bool,
) -> None:
    """
    Replace RRset zones by removing existing ones and adding new configurations.

    Args:
        uri: API endpoint URI
        ctx: Click context object
        settings: List of new zone configurations to import
        upstream_settings: List of existing upstream zone configurations
        setting_names: Set of zone names from the new settings
        ignore_errors: If True, continue processing despite errors
    """
    existing_upstreams = []
    upstreams_to_delete = []
    for zone_entry in upstream_settings:
        if zone_entry["name"] in setting_names:
            existing_upstreams.append(zone_entry)
        else:
            upstreams_to_delete.append(zone_entry)
    for zone_entry in settings:
        if zone_entry["name"] in [upstream["name"] for upstream in existing_upstreams]:
            r = http_delete(f"{uri}/{zone_entry['name']}", ctx)
            if r.status_code != 204:
                handle_import_early_exit(
                    {
                        "error": f"Failed removing rrset {zone_entry['name']} with status "
                        f"{r.status_code}({r.text}), aborting further "
                        f"configuration changes"
                    },
                    ignore_errors,
                )

        r = http_post(uri, ctx, payload=zone_entry)
        if r.status_code != 201:
            handle_import_early_exit(
                {
                    "error": f"Failed adding rrset {zone_entry['name']} with status "
                    f"{r.status_code}/({r.text}), aborting further "
                    "configuration changes"
                },
                ignore_errors,
            )

    for zone_entry in upstreams_to_delete:
        r = http_delete(f"{uri}/{zone_entry['name']}", ctx)
        if r.status_code != 204:
            handle_import_early_exit(
                {
                    "error": f"Failed deleting rrset {zone_entry['name']} with status "
                    f"{r.status_code} and body {r.text}, aborting "
                    "further configuration changes"
                },
                ignore_errors,
            )


def add_rrset_import(
    uri: str,
    ctx: click.Context,
    settings: list,
    upstream_settings: list,
    merge: bool,
    ignore_errors: bool,
) -> None:
    """
    Import RRset zones with optional merging and error handling.

    Args:
        uri: API endpoint URI
        ctx: Click context object
        settings: List of zone configurations to import
        upstream_settings: List of existing upstream zone configurations
        merge: If True, merge new settings with existing ones
        ignore_errors: If True, continue processing despite errors
    """

    for zone_entry in settings:
        payload = None
        if merge:
            for existing_zone in upstream_settings:
                if zone_entry["name"] == existing_zone["name"]:
                    payload = existing_zone.copy()
                    payload.update(zone_entry)
        if not payload:
            payload = zone_entry.copy()
        r = http_delete(f"{uri}/{zone_entry['name']}", ctx)
        if r.status_code != 204:
            handle_import_early_exit(
                {
                    "error": f"Failed deleting zone {payload['name']}, "
                    "aborting further configuration changes"
                },
                ignore_errors,
            )
        r = http_post(uri, ctx, payload=payload)
        if r.status_code != 201:
            handle_import_early_exit(
                {
                    "error": f"Failed adding zone {payload['name']}, "
                    f"aborting further configuration changes"
                },
                ignore_errors,
            )


def handle_import_early_exit(message: dict, ignore_errors: bool) -> None:
    """
    Handle import errors with configurable behavior based on ignore_errors flag.

    When ignore_errors is False (strict mode):
    - Prints error to stdout and exits immediately with code 1
    - Stops all further processing

    When ignore_errors is True (permissive mode):
    - Prints error to stderr but continues execution
    - Allows processing of remaining items

    Args:
        message: Dictionary containing error information (typically with 'error' key)
        ignore_errors: If True, log error and continue; if False, log error and exit
    """
    if ignore_errors:
        print_output(message, stderr=True)
    else:
        print_output(message)
        raise SystemExit(1)


def replace_tsigkey_import(
    uri: str, ctx: click.Context, settings: list, upstream_settings: list, ignore_errors: bool
) -> None:
    """
    Replace TSIG keys by performing a complete synchronization operation.

    This function ensures the upstream configuration exactly matches the provided settings by:
    1. Identifying which keys already exist and match (no action needed)
    2. Adding new keys that don't exist upstream
    3. Removing upstream keys that aren't in the new settings

    Args:
        uri: API endpoint URI for TSIG keys
        ctx: Click context object containing authentication and configuration
        settings: List of desired TSIG key configurations
        upstream_settings: List of current upstream TSIG key configurations
        ignore_errors: If True, continue processing despite individual failures
    """
    existing_upstreams = []
    upstreams_to_delete = []
    for upstream_tsigkey in upstream_settings:
        if upstream_tsigkey in settings:
            existing_upstreams.append(upstream_tsigkey)
        else:
            upstreams_to_delete.append(upstream_tsigkey)
    for new_tsigkey in settings:
        if new_tsigkey not in existing_upstreams:
            r = http_post(uri, ctx, payload=new_tsigkey)
            if r.status_code != 201:
                handle_import_early_exit(
                    {
                        "error": f"Failed adding tsigkey {new_tsigkey['name']} with status "
                        f"{r.status_code} and body {r.text}, "
                        "aborting further changes"
                    },
                    ignore_errors,
                )

    for upstream_tsigkey in upstreams_to_delete:
        r = http_delete(f"{uri}/{upstream_tsigkey['name']}", ctx)
        if r.status_code != 204:
            handle_import_early_exit(
                {
                    "error": f"Failed deleting tsigkey {upstream_tsigkey['name']}"
                    f" with status {r.status_code} and body {r.text}, "
                    f"aborting further changes"
                },
                ignore_errors,
            )


def add_tsigkey_import(uri: str, ctx: click.Context, settings: list, ignore_errors: bool) -> None:
    """
    Import TSIG keys by adding them to the upstream configuration.

    Accepts both successful creation (201) and conflicts (409) as valid outcomes,
    allowing for idempotent operations where existing keys are not modified.

    Args:
        uri: API endpoint URI for TSIG keys
        ctx: Click context object containing authentication and configuration
        settings: List of TSIG key configurations to import
        ignore_errors: If True, continue processing despite errors
    """

    for new_tsigkey in settings:
        r = http_post(f"{uri}", ctx, payload=new_tsigkey)
        if r.status_code not in (201, 409):
            handle_import_early_exit(
                {
                    "error": f"Failed adding tsigkey {new_tsigkey['name']}, "
                    f"aborting further configuration changes"
                },
                ignore_errors,
            )


def replace_view_import(
    uri: str, ctx: click.Context, settings: list, upstream_settings: list, ignore_errors: bool
) -> None:
    """
    Replace views by comparing current settings with upstream settings.

    This function performs a differential update:
    - Deletes views that exist in upstream but not in current settings
    - Adds new views that exist in current but not in upstream settings
    - For matching view names, adds/removes individual views based on set difference

    Args:
        uri: Database URI or connection string
        ctx: Click context object for CLI operations
        settings: Current view configuration (target state)
        upstream_settings: Previous view configuration (current state)
        ignore_errors: Whether to continue processing if errors occur
    """
    views_to_add = []
    views_to_delete = []
    for old_view in upstream_settings:
        # if a view name is not in the name set, delete it and its contents completely
        if old_view["name"] not in [viewset["name"] for viewset in settings]:
            for item in old_view["views"]:
                views_to_delete.append({"name": old_view["name"], "view": item})
            continue
        # the new view name is present, intersect the content
        for new_view in settings:
            if old_view["name"] == new_view["name"]:
                for item in new_view["views"].difference(old_view["views"]):
                    views_to_add.append({"name": old_view["name"], "view": item})
                for item in old_view["views"].difference(new_view["views"]):
                    views_to_delete.append({"name": old_view["name"], "view": item})
            if new_view["name"] not in [viewset["name"] for viewset in upstream_settings]:
                for item in new_view["views"]:
                    views_to_add.append({"name": new_view["name"], "view": item})

    add_views(views_to_add, uri, ctx, continue_on_error=ignore_errors)
    delete_views(views_to_delete, uri, ctx, continue_on_error=ignore_errors)


def add_view_import(uri: str, ctx: click.Context, settings: list, ignore_errors: bool) -> None:
    """
    Import views from settings configuration.

    Args:
        uri: The database URI or connection string
        ctx: Click context object for CLI operations
        settings: List of view configuration dictionaries, each containing
                 'name' and 'views' keys
        ignore_errors: Whether to continue processing if errors occur

    Raises:
        SystemExit: If subsequent requests encounter an error and ignore_errors is True
    """
    views_to_add = [
        {"name": view_entry["name"], "view": view_item}
        for view_entry in settings
        for view_item in view_entry["views"]
    ]

    if views_to_add:
        add_views(views_to_add, uri, ctx, continue_on_error=ignore_errors)
