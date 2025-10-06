"""
A Click-based CLI module for managing DNS zones in PowerDNS.

This module provides a comprehensive set of commands for managing DNS zones.

Commands:
    add: Adds a new DNS zone with a specified type and optional master servers.
    delete: Deletes a DNS zone, with an option to force deletion without confirmation.
    export: Exports a zone's configuration in JSON or BIND format.
    flush-cache: Flushes the cache for a specified zone.
    import: Imports a zone from a file, with options to force or merge configurations.
    notify: Notifies slave servers of changes to a zone.
    rectify: Rectifies a zone, ensuring DNSSEC consistency.
    search: Performs a full-text search in the RRSET database.
    list: Lists all configured zones on the DNS server.
    spec: Opens the zone API specification in the browser.
"""

from typing import Any

import click

from ..utils import main as utils
from ..utils.validation import IPAddress, PowerDNSZone


@click.group()
def zone():
    """Manage zones"""


@zone.command("add")
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.argument(
    "zonetype",
    type=click.Choice(["MASTER", "NATIVE", "SLAVE"], case_sensitive=False),
)
@click.option(
    "-m", "--master", type=IPAddress, help="Set Zone Masters", default=None, multiple=True
)
@click.pass_context
def zone_add(ctx, dns_zone, zonetype, master):
    """
    Adds a new zone.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones"
    payload = {
        "name": dns_zone,
        "kind": zonetype.capitalize(),
        "masters": master,
    }
    current_zones = query_zones(ctx)
    if [z for z in current_zones if z["name"] == dns_zone]:
        utils.print_output({"message": f"Zone {dns_zone} already present"})
        raise SystemExit(0)
    r = utils.http_post(uri, ctx, payload)
    if utils.create_output(r, (201,), optional_json={"message": f"Zone {dns_zone} created"}):
        raise SystemExit(0)
    raise SystemExit(1)


@zone.command("delete")
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.option(
    "-f",
    "--force",
    help="Force execution and skip confirmation",
    is_flag=True,
    default=False,
    show_default=True,
)
@click.pass_context
def zone_delete(ctx, dns_zone, force):
    """
    Deletes a Zone.
    """
    upstream_zones = query_zones(ctx)
    if dns_zone not in [single_zone["name"] for single_zone in upstream_zones]:
        utils.print_output({"message": f"{dns_zone} already absent"})
        raise SystemExit(0)

    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}"
    warning = f"!!!! WARNING !!!!!\nYou are attempting to delete {dns_zone}\nAre you sure?"
    if not force and not click.confirm(warning):
        utils.print_output({"message": f"Aborted deleting {dns_zone}"})
        raise SystemExit(1)
    r = utils.http_delete(uri, ctx)
    msg = {"message": f"{dns_zone} deleted"}
    if utils.create_output(r, (204,), optional_json=msg):
        raise SystemExit(0)
    raise SystemExit(1)


@zone.command("export")
@click.pass_context
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.option(
    "-b",
    "--bind",
    help="Use bind format as output",
    is_flag=True,
    default=False,
)
def zone_export(ctx, dns_zone, bind):
    """
    Export the whole zone configuration, either as JSON or BIND
    """
    if bind:
        uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/export"
        r = utils.http_get(uri, ctx)
        if utils.create_output(r, (200,), output_text=True):
            raise SystemExit(0)
        raise SystemExit(1)
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@zone.command("flush-cache")
@click.pass_context
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
def zone_flush_cache(ctx, dns_zone):
    """Flushes the cache of the given zone"""
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/cache/flush"
    r = utils.http_put(uri, ctx, params={"domain": dns_zone})
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@zone.command("import")
@click.argument("file", type=click.File())
@click.option(
    "-f",
    "--force",
    help="Force execution and skip confirmation",
    is_flag=True,
)
@click.option(
    "-m",
    "--merge",
    help="Merge new configuration with exisiting settings",
    is_flag=True,
)
@click.pass_context
def zone_import(ctx, file, force, merge):
    """
    Directly import zones into the server. Must delete the zone beforehand, since
    most settings may not be changed after a zone is created.
    This might have side effects for other settings, as cryptokeys are associated with a zone!
    """
    settings = utils.extract_file(file)
    validate_zone_import(settings)
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{settings['id']}"
    upstream_settings = utils.read_settings_from_upstream(uri, ctx)
    check_zones_for_identical_content(settings, upstream_settings)
    warning = (
        f"!!!! WARNING !!!!!\nYou are deleting and reconfiguring {settings['id']}!\n"
        "Are you sure?"
    )
    if not force and not click.confirm(warning):
        utils.print_output({"error": "Aborted"})
        raise SystemExit(1)
    import_zone_settings(
        uri, ctx, settings, upstream_settings=upstream_settings, merge=merge, ignore_errors=False
    )
    utils.print_output(
        {"message": "Successfully imported zones"},
    )
    raise SystemExit(0)


@zone.command("notify")
@click.pass_context
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
def zone_notify(ctx, dns_zone):
    """
    Let the server notify its slaves of changes to the given zone

    Fails when the zone kind is neither master or slave, or master and slave are
    disabled in the configuration. Only works for slave if renotify is enabled.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/notify"
    r = utils.http_put(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@zone.command("rectify")
@click.pass_context
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
def zone_rectify(ctx, dns_zone):
    """
    Rectifies a given zone. Will fail on slave zones and zones without dnssec.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/rectify"
    r = utils.http_put(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@zone.command("spec")
def zone_spec():
    """Open the zone specification on https://redocly.github.io"""

    utils.open_spec("zone")


@zone.command("search")
@click.argument("search-string", metavar="STRING")
@click.option("--max", "max_output", help="Number of items to output", default=5, type=click.INT)
@click.pass_context
def zone_search(ctx, search_string, max_output):
    """Do fulltext search in the rrset database. Use wildcards in your string to ignore leading
    or trailing characters"""
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/search-data"
    r = utils.http_get(
        uri,
        ctx,
        params={"q": f"{search_string}", "max": max_output},
    )
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@zone.command("list")
@click.pass_context
def zone_list(ctx):
    """
    Shows all configured zones on this dns server, does not display their RRSETs
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


def check_zones_for_identical_content(
    new_settings: dict[str, Any], upstream_settings: dict[str, Any]
) -> None:
    """Check if the new settings are identical to the upstream settings, ignoring serial keys.

    This function compares two dictionaries of settings,
    excluding the 'edited_serial' and 'serial' keys,
    and exits with a success code if they are identical.

    Args:
        new_settings: Dictionary containing the new settings to be checked.
        upstream_settings: Dictionary containing the upstream settings to compare against.

    Raises:
        SystemExit: If the settings are identical (excluding serial keys), exits with code 0.
    """
    tmp_new_settings = new_settings.copy()
    tmp_upstream_settings = upstream_settings.copy()

    for key in ("edited_serial", "serial"):
        tmp_new_settings.pop(key, None)
        tmp_upstream_settings.pop(key, None)

    if all(
        tmp_new_settings.get(key) == tmp_upstream_settings.get(key)
        for key in tmp_new_settings.keys()
    ):
        utils.print_output({"message": "Required settings are already present."})
        raise SystemExit(0)


def import_zone_settings(
    uri: str,
    ctx: click.Context,
    settings: dict,
    upstream_settings: dict,
    merge: bool,
    ignore_errors: bool,
) -> None:
    """
    Import a zone with optional merging and error handling.

    Args:
        uri: API endpoint URI
        ctx: Click context object
        settings: List of zone configurations to import
        upstream_settings: List of existing upstream zone configurations
        merge: If True, merge new settings with existing ones
        ignore_errors: If True, continue processing despite errors
    """

    if merge:
        payload = upstream_settings | settings
    else:
        payload = settings.copy()
    r = utils.http_delete(f"{uri}", ctx)
    if r.status_code not in (204, 404):
        utils.handle_import_early_exit(
            ctx,
            f"Failed deleting zone {payload['id']} aborting further configuration changes",
            ignore_errors,
        )
    r = utils.http_post(uri.removesuffix("/" + payload["id"]), ctx, payload=payload)
    if r.status_code != 201:
        utils.handle_import_early_exit(
            ctx,
            f"Failed adding zone {payload['id']}",
            ignore_errors,
        )


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
    r = utils.http_get(f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones", ctx)
    if r.status_code != 200:
        utils.print_output({"error": r.json()})
        raise SystemExit(1)
    return r.json()


def validate_zone_import(zone_to_import: dict) -> None:
    """
    Validates the structure and content of a zone dictionary for import.

    Args:
        zone_to_import: A dictionary representing the zone to validate.
            Expected to contain either 'id' or 'name'.

    Raises:
        SystemExit: Exits with status 1 if validation fails.
    """
    if not isinstance(zone_to_import, dict):
        utils.print_output({"error": "You must supply a single zone"})
        raise SystemExit(1)

    if not zone_to_import.get("id") and not zone_to_import.get("name"):
        utils.print_output(
            {"error": "Either 'name' or 'id' must be present to determine the zone."}
        )
        raise SystemExit(1)

    if zone_to_import.get("name") and not zone_to_import.get("id"):
        zone_to_import["id"] = zone_to_import["name"]
