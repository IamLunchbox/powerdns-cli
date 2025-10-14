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

from typing import NoReturn

import click

from ..utils import main as utils
from ..utils.validation import DefaultCommand, IPRange


@click.group()
def network():
    """Set up networks views.
    A view contains a list of domains, each member of the view may access.
    The network endpoint manages these view members.
    Members consist of IP-address ranges and may include public and private ones.
    If anyone may query the zones of a view, 0.0.0.0/0 is a valid view member.
    """


@network.command(
    "add",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.pass_context
@click.argument("cidr", type=IPRange)
@click.argument("view_id", type=click.STRING, metavar="view")
def network_add(ctx: click.Context, cidr: str, view_id: str, **kwargs) -> NoReturn:
    """
    Add a view of a zone to a specific network.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/networks/{cidr}"
    current_network = utils.http_get(uri, ctx)
    if current_network.status_code == 200 and current_network.json()["view"] == view_id:
        ctx.obj.logger.info(f"Network {cidr} is already assigned to view {view_id}.")
        utils.exit_action(
            ctx,
            success=True,
            message=f"Network {cidr} is already assigned to view {view_id}.",
        )
    payload = {"view": view_id}
    r = utils.http_put(uri, ctx, payload=payload)
    if r.status_code == 204:
        ctx.obj.logger.info(f"Added view {view_id} to {cidr}.")
        utils.exit_action(ctx, success=True, message=f"Added view {view_id} to {cidr}.")
    else:
        ctx.obj.logger.error(f"Failed to add view {view_id} to {cidr}: {r.status_code}.")
        utils.exit_action(
            ctx,
            success=False,
            message=f"Failed to add view {view_id} to {cidr}: HTTP {r.status_code}.",
        )


@network.command(
    "list",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
)
@click.pass_context
def network_list(ctx: click.Context, **kwargs):
    """
    List all registered networks and views.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/networks"
    utils.show_setting(ctx, uri, "network", "list")


@network.command(
    "delete",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.pass_context
@click.argument("cidr", type=IPRange)
def network_delete(ctx: click.Context, cidr: str, **kwargs) -> NoReturn:
    """
    Remove a view association from a specific network.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/networks/{cidr}"
    ctx.obj.logger.info(f"Attempting to delete view association for network: {cidr}.")
    current_network = utils.http_get(uri, ctx)
    if current_network.status_code == 404:
        ctx.obj.logger.info(f"Network {cidr} not found.")
        utils.exit_action(ctx, success=True, message=f"Network {cidr} is absent.")
    payload = {"view": ""}
    r = utils.http_put(uri, ctx, payload=payload)
    if r.status_code == 204:
        ctx.obj.logger.info(f"Successfully removed view association from {cidr}.")
        utils.exit_action(ctx, success=True, message=f"Removed view association from {cidr}.")
    else:
        ctx.obj.logger.error(
            f"Failed to remove view association from {cidr}. Status code: {r.status_code}."
        )
        utils.exit_action(
            ctx,
            success=False,
            message=f"Failed to remove view association from {cidr}.",
            response=r,
        )


@network.command(
    "export",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.pass_context
@click.argument("cidr", type=IPRange)
def network_export(ctx: click.Context, cidr: str, **kwargs):
    """
    Show the network and its associated views.
    When not netmask is provided, it defaults to /32 or /128.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/networks/{cidr}"
    ctx.obj.logger.info(f"Exporting network: {cidr}.")
    utils.show_setting(ctx, uri, "network", "export")


@network.command(
    "import",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.pass_context
@click.argument("file", type=click.File())
@click.option(
    "--replace",
    type=click.BOOL,
    is_flag=True,
    help="Replace all network settings with new ones.",
)
@click.option(
    "--ignore-errors",
    type=click.BOOL,
    is_flag=True,
    help="Continue import even when requests fail.",
)
def network_import(
    ctx: click.Context, file: click.File, replace: bool, ignore_errors: bool, **kwargs
) -> NoReturn:
    """Import network and zone assignments.
    File format:
    {"networks": [{"network": str, "view": str}]}
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/networks"
    ctx.obj.logger.info(f"Importing networks from file: {file.name}.")
    nested_settings = utils.extract_file(ctx, file)
    if not isinstance(nested_settings, dict) or not isinstance(
        nested_settings.get("networks"), list
    ):
        ctx.obj.logger.error(
            "Invalid file format: Networks must be a dict with the key 'networks'."
        )
        utils.exit_action(
            ctx,
            success=False,
            message="Invalid file format: Networks must be a dict with the key 'networks'.",
        )
    settings = nested_settings["networks"]
    upstream_settings = utils.read_settings_from_upstream(uri, ctx)
    if isinstance(upstream_settings.get("networks"), list):
        upstream_settings = upstream_settings["networks"]
    else:
        upstream_settings = []
    if replace and upstream_settings == settings:
        ctx.obj.logger.info("Requested networks are already present.")
        utils.exit_action(ctx, success=True, message="Requested networks are already present.")
    if not replace and all(item in upstream_settings for item in settings):
        ctx.obj.logger.info("Requested networks are already present.")
        utils.exit_action(ctx, success=True, message="Requested networks are already present.")
    if replace and upstream_settings:
        replace_network_import(uri, ctx, settings, upstream_settings, ignore_errors)
    else:
        add_network_import(uri, ctx, settings, ignore_errors)


@network.command("spec")
def network_spec():
    """Open the network specification on https://redocly.github.io."""
    utils.open_spec("network")


def replace_network_import(
    uri: str,
    ctx: click.Context,
    settings: list[dict],
    upstream_settings: list[dict],
    ignore_errors: bool,
) -> NoReturn:
    """Replaces network configurations by adding new entries and removing obsolete ones.
    This function compares the provided `settings` with `upstream_settings` to determine which
    network configurations to add or delete.
    It sends PUT requests to update or remove network configurations as needed.
    If an error occurs, it either logs the error and continues (if `ignore_errors` is True) or
    aborts the process.
    Args:
        uri: The base URI for API requests.
        ctx: Click context object for command-line operations.
        settings: List of dictionaries representing desired network configurations.
        upstream_settings: List of dictionaries representing upstream configurations.
        ignore_errors: If True, continues execution after errors instead of aborting.
    """
    existing_upstreams = []
    upstreams_to_delete = []
    for network_item in upstream_settings:
        if network_item in settings:
            existing_upstreams.append(network_item)
        else:
            upstreams_to_delete.append(network_item)
    for network_item in upstreams_to_delete:
        ctx.obj.logger.info(
            f"Removing network {network_item['network']} from view {network_item['view']}."
        )
        r = utils.http_put(f"{uri}/{network_item['network']}", ctx, payload={"view": ""})
        if r.status_code != 204:
            ctx.obj.logger.error(
                f"Failed to remove network {network_item['network']} "
                f"from view {network_item['view']}."
            )
            if not ignore_errors:
                utils.exit_action(
                    ctx,
                    success=False,
                    response=r,
                    message=f"Failed to remove network {network_item['network']} "
                    f"from view {network_item['view']}.",
                )
    for network_item in settings:
        if network_item not in existing_upstreams:
            ctx.obj.logger.info(
                f"Adding network {network_item['network']} to view {network_item['view']}."
            )
            r = utils.http_put(
                f"{uri}/{network_item['network']}",
                ctx,
                payload={"view": network_item["view"]},
            )
            if r.status_code != 204:
                ctx.obj.logger.error(
                    f"Failed to add network {network_item['network']} to "
                    f"view {network_item['view']}."
                )
                if not ignore_errors:
                    utils.exit_action(
                        ctx,
                        success=False,
                        response=r,
                        message=f"Failed to add network {network_item['network']} to "
                        f"view {network_item['view']}.",
                    )
    ctx.obj.logger.info("Network import completed successfully.")
    utils.exit_action(ctx, success=True, message="Network import completed successfully.")


def add_network_import(
    uri: str,
    ctx: click.Context,
    settings: list[dict],
    ignore_errors: bool,
) -> NoReturn:
    """Adds network configurations from an import using HTTP PUT requests.
    This function iterates through the provided `settings` and sends a PUT request
    for each network item to the specified URI.
    If the request fails, it either logs the error and continues (if `ignore_errors` is True) or
    aborts the process.
    Args:
        uri: The base URI for API requests.
        ctx: Click context object for command-line operations.
        settings: List of dictionaries representing network configurations to add.
        ignore_errors: If True, continues execution after errors instead of aborting.
    """
    for network_item in settings:
        ctx.obj.logger.info(
            f"Adding network {network_item['network']} to view {network_item['view']}."
        )
        r = utils.http_put(
            f"{uri}/{network_item['network']}",
            ctx,
            payload={"view": network_item["view"]},
        )
        if r.status_code != 204:
            ctx.obj.logger.error(
                f"Failed to add network {network_item['network']} to view {network_item['view']}."
            )
            if not ignore_errors:
                utils.exit_action(
                    ctx,
                    success=False,
                    response=r,
                    message=f"Failed to add network {network_item['network']} to "
                    f"view {network_item['view']}.",
                )
    ctx.obj.logger.info("Network addition completed successfully.")
    utils.exit_action(ctx, success=True, message="Network addition completed successfully.")
