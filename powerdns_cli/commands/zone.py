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

from typing import Any, NoReturn

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
def zone_add(
    ctx: click.Context, dns_zone: str, zonetype: str, master: tuple[IPAddress, ...]
) -> NoReturn:
    """
    Adds a new zone.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones"
    payload = {
        "name": dns_zone,
        "kind": zonetype.capitalize(),
        "masters": list(master),
    }

    current_zones = query_zones(ctx)
    if [z for z in current_zones if z["name"] == dns_zone]:
        ctx.obj.logger.info(f"Zone {dns_zone} already present.")
        utils.exit_action(ctx, success=True, message=f"Zone {dns_zone} already present.")

    ctx.obj.logger.info(f"Adding zone {dns_zone}.")
    r = utils.http_post(uri, ctx, payload)

    if r.status_code == 201:
        ctx.obj.logger.info(f"Successfully created {dns_zone}.")
        utils.exit_action(
            ctx, success=True, message=f"Successfully created {dns_zone}.", response=r
        )
    else:
        ctx.obj.logger.error(f"Failed to create zone {dns_zone}.")
        utils.exit_action(
            ctx, success=False, message=f"Failed to create zone {dns_zone}.", response=r
        )


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
def zone_delete(ctx: click.Context, dns_zone: str, force: bool) -> NoReturn:
    """
    Deletes a Zone.
    """
    upstream_zones = query_zones(ctx)
    if dns_zone not in [single_zone["name"] for single_zone in upstream_zones]:
        ctx.obj.logger.info(f"Zone {dns_zone} already absent.")
        utils.exit_action(ctx, success=True, message=f"Zone {dns_zone} already absent")

    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}"
    warning = f"!!!! WARNING !!!!!\nYou are attempting to delete {dns_zone}\nAre you sure?"

    if not force and not click.confirm(warning):
        ctx.obj.logger.info(f"Aborted deleting {dns_zone}.")
        utils.exit_action(ctx, success=False, message=f"Aborted deleting {dns_zone}.")

    ctx.obj.logger.info(f"Deleting zone: {dns_zone}.")
    r = utils.http_delete(uri, ctx)

    if r.status_code == 204:
        ctx.obj.logger.info(f"Successfully deleted {dns_zone}.")
        utils.exit_action(ctx, success=True, message=f"Successfully deleted {dns_zone}", response=r)
    else:
        ctx.obj.logger.error(f"Failed to delete zone {dns_zone}")
        utils.exit_action(
            ctx, success=False, message=f"Failed to delete zone {dns_zone}.", response=r
        )


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
def zone_export(ctx: click.Context, dns_zone: str, bind: bool) -> NoReturn:
    """
    Export the whole zone configuration, either as JSON or BIND
    """
    if bind:
        ctx.obj.logger.info(f"Exporting {dns_zone} in BIND format.")
        uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/export"
        r = utils.http_get(uri, ctx)
        if r.status_code == 200:
            ctx.obj.handler.set_message(r.text)
            ctx.obj.handler.set_data(r)
            ctx.obj.handler.set_success()
            utils.exit_cli(ctx)
        elif r.status_code == 404:
            ctx.obj.handler.set_message(f"Failed exporting {dns_zone}, not found.")
            ctx.obj.handler.set_success(False)
            utils.exit_cli(ctx)
        ctx.obj.handler.set_message(f"Failed exporting {dns_zone}, unknown error.")
        ctx.obj.handler.set_success(False)
        utils.exit_cli(ctx)
    ctx.obj.logger.info(f"Exporting {dns_zone} as JSON.")
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}"
    utils.show_setting(ctx, uri, "zone", "export")


@zone.command("flush-cache")
@click.pass_context
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
def zone_flush_cache(ctx: click.Context, dns_zone: str) -> NoReturn:
    """Flushes the cache of the given zone"""
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/cache/flush"
    ctx.obj.logger.info(f"Flushing cache for zone: {dns_zone}.")
    r = utils.http_put(uri, ctx, params={"domain": dns_zone})

    if r.status_code == 200:
        ctx.obj.logger.info(f"Successfully flushed cache for {dns_zone}.")
        utils.exit_action(
            ctx, success=True, message=f"Successfully flushed cache for {dns_zone}.", response=r
        )
    else:
        ctx.obj.logger.error(f"Failed to flush cache for {dns_zone}: {r.status_code} {r.text}")
        utils.exit_action(
            ctx, success=False, message=f"Failed to flush cache for {dns_zone}.", response=r
        )


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
    help="Merge new configuration with existing settings",
    is_flag=True,
)
@click.pass_context
def zone_import(ctx: click.Context, file: click.File, force: bool, merge: bool) -> NoReturn:
    """
    Directly import zones into the server. Must delete the zone beforehand, since
    most settings may not be changed after a zone is created.
    This might have side effects for other settings, as cryptokeys are associated with a zone!
    """
    ctx.obj.logger.info("Importing zone configuration from file.")
    settings = utils.extract_file(file)
    validate_zone_import(ctx, settings)
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{settings['id']}"
    upstream_settings = utils.read_settings_from_upstream(uri, ctx)
    check_zones_for_identical_content(ctx, settings, upstream_settings)

    warning = (
        f"!!!! WARNING !!!!!\nYou are deleting and reconfiguring {settings['id']}!\n"
        "Are you sure?"
    )

    if not force and not click.confirm(warning):
        ctx.obj.logger.error("Zone import aborted by user")
        utils.exit_action(ctx, success=False, message="Zone import aborted by user.")

    ctx.obj.logger.info(f"Importing zone {settings['id']}.")
    import_zone_settings(uri, ctx, settings, upstream_settings=upstream_settings, merge=merge)


@zone.command("notify")
@click.pass_context
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
def zone_notify(ctx: click.Context, dns_zone: str) -> NoReturn:
    """
    Let the server notify its slaves of changes to the given zone.
    Fails when the zone kind is neither master nor slave, or master and slave are
    disabled in the configuration. Only works for slave if renotify is enabled.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/notify"
    ctx.obj.logger.info(f"Sending notify request for zone: {dns_zone}.")
    r = utils.http_put(uri, ctx)

    if r.status_code == 200:
        ctx.obj.logger.info(f"Successfully notified slaves for zone: {dns_zone}.")
        utils.exit_action(ctx, True, f"Successfully notified slaves for zone: {dns_zone}.", r)
    else:
        ctx.obj.logger.error(f"Failed to notify slaves for zone: {dns_zone}.")
        utils.exit_action(ctx, False, f"Failed to notify slaves for zone: {dns_zone}.", r)


@zone.command("rectify")
@click.pass_context
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
def zone_rectify(ctx: click.Context, dns_zone: str) -> NoReturn:
    """
    Rectifies a given zone. Will fail on slave zones and zones without DNSSEC.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/rectify"
    ctx.obj.logger.info(f"Attempting to rectify zone: {dns_zone}")
    r = utils.http_put(uri, ctx)

    if r.status_code == 200:
        ctx.obj.logger.info(f"Successfully rectified zone: {dns_zone}")
        utils.exit_action(ctx, True, f"Successfully rectified zone: {dns_zone}", r)
    else:
        ctx.obj.logger.error(f"Failed to rectify zone: {dns_zone}, status code: {r.status_code}")
        utils.exit_action(ctx, False, f"Failed to rectify zone: {dns_zone}", r)


@zone.command("spec")
def zone_spec():
    """Open the zone specification on https://redocly.github.io"""

    utils.open_spec("zone")


@zone.command("search")
@click.argument("search-string", metavar="STRING")
@click.option("--max", "max_output", help="Number of items to output", default=5, type=click.INT)
@click.pass_context
def zone_search(ctx: click.Context, search_string: str, max_output: int) -> NoReturn:
    """
    Do fulltext search in the rrset database.
    Use wildcards in your string to ignore leading or trailing characters.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/search-data"
    ctx.obj.logger.info(f"Searching for '{search_string}' with max output {max_output}.")
    r = utils.http_get(uri, ctx, params={"q": search_string, "max": max_output})

    if r.status_code == 200:
        ctx.obj.logger.info("Successfully completed search.")
        utils.exit_action(
            ctx, success=True, message="Successfully completed search.", response=r, print_data=True
        )
    else:
        ctx.obj.logger.error("Failed searching zones.")
        utils.exit_action(ctx, success=False, message="Failed searching zones.", response=r)


@zone.command("list")
@click.pass_context
def zone_list(ctx: click.Context) -> NoReturn:
    """
    Shows all configured zones on this dns server, does not display their RRSETs
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones"
    utils.show_setting(ctx, uri, "zone", "list")


def check_zones_for_identical_content(
    ctx: click.Context, new_settings: dict[str, Any], upstream_settings: dict[str, Any]
) -> None:
    """Check if the new settings are identical to the upstream settings, ignoring serial keys.

    This function compares two dictionaries of settings, excluding 'edited_serial' and 'serial',
    and exits with a success code if they are identical.

    Args:
        ctx: Click context object.
        new_settings: Dictionary containing the new settings to be checked.
        upstream_settings: Dictionary containing the upstream settings to compare against.
    """
    ctx.obj.logger.info("Checking if current zone settings are identical to new ones.")
    tmp_new_settings = new_settings.copy()
    tmp_upstream_settings = upstream_settings.copy()

    for key in ("edited_serial", "serial"):
        tmp_new_settings.pop(key, None)
        tmp_upstream_settings.pop(key, None)

    if all(
        tmp_new_settings.get(key) == tmp_upstream_settings.get(key)
        for key in tmp_new_settings.keys()
    ):
        ctx.obj.logger.info("Required settings are already present.")
        utils.exit_action(ctx, success=True, message="Required settings are already present.")
    else:
        ctx.obj.logger.info("Settings differ; proceeding with further actions.")


def import_zone_settings(
    uri: str,
    ctx: click.Context,
    settings: dict[str, Any],
    upstream_settings: dict[str, Any],
    merge: bool,
) -> NoReturn:
    """
    Import a zone with optional merging and error handling.

    Args:
        uri: API endpoint URI.
        ctx: Click context object.
        settings: Dictionary of zone configurations to import.
        upstream_settings: Dictionary of existing upstream zone configurations.
        merge: If True, merge new settings with existing ones.
    """
    if merge:
        payload = upstream_settings | settings
    else:
        payload = settings.copy()

    ctx.obj.logger.info(f"Deleting zone {payload['id']} to submit new settings.")
    r = utils.http_delete(f"{uri}", ctx)
    if r.status_code not in (204, 404):
        ctx.obj.logger.error(f"Failed deleting zone {payload['id']}.")
        utils.exit_action(
            ctx, success=False, message=f"Failed deleting zone {payload['id']}.", response=r
        )
    ctx.obj.logger.info(
        f"Zone {payload['id']} deleted or was not present; proceeding to add new settings."
    )

    r = utils.http_post(uri.removesuffix(f"/{payload['id']}"), ctx, payload=payload)
    if r.status_code == 201:
        ctx.obj.logger.info(f"Successfully re-added {payload['id']}.")
        utils.exit_action(
            ctx, success=True, message=f"Successfully re-added {payload['id']}.", response=r
        )
    ctx.obj.logger.error(f"Failed adding zone {payload['id']}.")
    utils.exit_action(
        ctx, success=False, message=f"Failed adding zone {payload['id']}.", response=r
    )


def query_zones(ctx: click.Context) -> list[dict]:
    """Fetches and returns all zones configured on the DNS server.

    Sends a GET request to the DNS server's API endpoint to retrieve the list of zones.
    If the request fails (non-200 status code), it logs the error and exits.
    Otherwise, it exits with the list of zones.

    Args:
        ctx: Click context object containing the API host and other configuration.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones"
    ctx.obj.logger.info("Fetching zones.")
    r = utils.http_get(uri, ctx)

    if r.status_code == 200:
        ctx.obj.logger.info(f"Successfully fetched {len(r.json())} zones.")
        return r.json()
    ctx.obj.logger.error("Failed to fetch zones.")
    utils.exit_action(ctx, success=False, message="Failed to fetch zones.", response=r)


def validate_zone_import(ctx: click.Context, zone_to_import: dict[str, Any]) -> None:
    """
    Validates the structure and content of a zone dictionary for import.

    Args:
        ctx: Click context object.
        zone_to_import: A dictionary representing the zone to validate.
            Expected to contain either 'id' or 'name'.
    """
    if not isinstance(zone_to_import, dict):
        ctx.obj.logger.error("You must supply a single zone.")
        utils.exit_action(ctx, success=False, message="You must supply a single zone.")

    utils.is_id_or_name_present(ctx, zone_to_import)

    if zone_to_import.get("name") and not zone_to_import.get("id"):
        zone_to_import["id"] = zone_to_import["name"]
        ctx.obj.logger.info("Set 'id' from 'name'.")
    ctx.obj.logger.info("Validated zone import file.")
