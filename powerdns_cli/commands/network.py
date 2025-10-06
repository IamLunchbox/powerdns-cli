"""
A Click-based CLI module for managing network views in PowerDNS.

This module provides commands for managing network-based access control for DNS zones,
allowing administrators to associate networks (in CIDR notation) with specific views.

Commands:
    add: Associates a network (CIDR) with a specific view.
    delete: Removes a network's association with a view.
    export: Displays the network and its associated view.
    import: Imports network-view associations from a file, with options to replace or ignore errors.
    list: Lists all registered networks and their associated views.
    spec: Opens the network API specification in the browser.
"""

import click

from ..utils import main as utils
from ..utils.validation import IPRange


@click.group()
@click.pass_context
def network(ctx):
    """Shows and sets up network views to limit access to dns entries"""
    if ctx.obj.config["major_version"] < 5:
        utils.print_output({"error": "Your authoritative dns-server does not support networks"})
        raise SystemExit(1)


@network.command("add")
@click.argument("cidr", type=IPRange)
@click.argument("view_id", type=click.STRING, metavar="view")
@click.pass_context
def network_add(ctx, cidr, view_id):
    """
    Add a view of a zone to a specific network.
    Deleting requires passing an empty string to as view argument.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/networks/{cidr}"
    current_network = utils.http_get(uri, ctx)
    if current_network.status_code == 200 and current_network.json()["view"] == view_id:
        utils.print_output({"message": f"Network {cidr} is already assigned to view {view_id}"})
        raise SystemExit(0)
    payload = {"view": view_id}
    r = utils.http_put(uri, ctx, payload=payload)
    if utils.create_output(r, (204,), optional_json={"message": f"Added view {view_id} to {cidr}"}):
        raise SystemExit(0)
    raise SystemExit(1)


@network.command("list")
@click.pass_context
def network_list(ctx):
    """
    List all registered networks and views
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/networks"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@network.command("delete")
@click.argument("cidr", type=IPRange)
@click.pass_context
def network_delete(ctx, cidr):
    """
    Add a view of a zone to a specific network.
    Deleting requires passing an empty string to as view argument.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/networks/{cidr}"
    current_network = utils.http_get(uri, ctx)
    if current_network.status_code == 404:
        utils.print_output({"message": f"Network {cidr} absent"})
        raise SystemExit(0)
    payload = {"view": ""}
    r = utils.http_put(uri, ctx, payload=payload)
    if utils.create_output(
        r, (204,), optional_json={"message": f"Removed view association from {cidr}"}
    ):
        raise SystemExit(0)
    raise SystemExit(1)


@network.command("export")
@click.argument("cidr", type=IPRange)
@click.pass_context
def network_export(ctx, cidr):
    """
    Show the network and its associated views, defaults to /32 if no netmask is provided.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/networks/{cidr}"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@network.command("import")
@click.argument("file", type=click.File())
@click.option(
    "--replace",
    type=click.BOOL,
    is_flag=True,
    help="Replace all network settings with new ones",
)
@click.option(
    "--ignore-errors", type=click.BOOL, is_flag=True, help="Continue import even when requests fail"
)
@click.pass_context
def network_import(ctx, file, replace, ignore_errors):
    """Import network and zone assignments.
    File-example: {"networks": [{"network": "0.0.0.0/0", "view": "test"}]}"""
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/networks"
    nested_settings = utils.extract_file(file)
    if not isinstance(nested_settings, dict) or not isinstance(
        nested_settings.get("networks", None), list
    ):
        utils.print_output({"error": "Networks must be dict with the key networks"})
        raise SystemExit(1)
    settings = nested_settings["networks"]
    upstream_settings = utils.read_settings_from_upstream(uri, ctx)
    if isinstance(upstream_settings.get("networks", None), list):
        upstream_settings = upstream_settings["networks"]
    else:
        upstream_settings = []
    if replace and upstream_settings == settings:
        utils.print_output({"message": "Requested networks are already present"})
        raise SystemExit(0)
    if not replace and all(item in upstream_settings for item in settings):
        utils.print_output({"message": "Requested networks are already present"})
        raise SystemExit(0)
    if replace and upstream_settings:
        replace_network_import(uri, ctx, settings, upstream_settings, ignore_errors)
    else:
        add_network_import(uri, ctx, settings, ignore_errors)
    utils.print_output(
        {"message": "Successfully imported networks to views"},
    )
    raise SystemExit(0)


@network.command("spec")
def network_spec():
    """Open the network specification on https://redocly.github.io"""

    utils.open_spec("network")


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
    for network_item in upstreams_to_delete:
        r = utils.http_put(f"{uri}/{network_item['network']}", ctx, payload={"view": ""})
        if r.status_code != 204:
            utils.handle_import_early_exit(
                ctx,
                f"Failed adding network {network_item['network']} from new {network_item['view']}",
                ignore_errors,
            )
    for network_item in settings:
        if network_item not in existing_upstreams:
            r = utils.http_put(
                f"{uri}/{network_item['network']}", ctx, payload={"view": network_item["view"]}
            )
            if r.status_code != 204:
                utils.handle_import_early_exit(
                    ctx,
                    f"Failed adding '{network_item['network']}' to '{network_item['view']}'",
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
        r = utils.http_put(
            f"{uri}/{network_item['network']}", ctx, payload={"view": network_item["view"]}
        )
        if r.status_code != 204:
            utils.handle_import_early_exit(
                ctx,
                f"Failed adding network {network_item['network']} from new {network_item['view']}",
                ignore_errors,
            )
