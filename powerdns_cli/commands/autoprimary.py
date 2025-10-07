"""
A Click-based CLI module for managing autoprimary DNS server configurations.

This module provides commands to add and manage autoprimary upstream DNS servers.

Commands:
    add: Adds a new autoprimary upstream DNS server with the specified IP and nameserver.
    list: Lists all currently configured autoprimaries.
    import: Imports a file with autoprimary settings to the server.
    delete: Deletes an autoprimary upstream DNS server with the specified IP and nameserver.
"""

import click

from ..utils import main as utils
from ..utils.validation import AutoprimaryZone, IPAddress


@click.group()
def autoprimary():
    """Set up autoprimary configuration"""


@autoprimary.command("add")
@click.argument("ip", type=IPAddress)
@click.argument("nameserver", type=AutoprimaryZone)
@click.option("-a", "--account", default="", type=click.STRING, help="Option")
@click.pass_context
def autoprimary_add(
    ctx,
    ip,
    nameserver,
    account,
):
    """
    Adds an autoprimary upstream dns server
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/autoprimaries"
    payload = {"ip": ip, "nameserver": nameserver, "account": account}
    if is_autoprimary_present(uri, ctx, ip, nameserver):
        utils.exit_action(
            ctx,
            success=True,
            message=f"Autoprimary {ip} with nameserver {nameserver} already present",
        )
    r = utils.http_post(uri, ctx, payload)
    if r.status_code == 201:
        utils.exit_action(ctx, success=True, message=f"Autoprimary {ip}/{nameserver} added")
    utils.exit_action(ctx, success=False, message=f"Failed adding {ip}/{nameserver}")


@autoprimary.command("delete")
@click.argument("ip", type=IPAddress)
@click.argument("nameserver", type=AutoprimaryZone)
@click.pass_context
def autoprimary_delete(ctx, ip, nameserver):
    """
    Deletes an autoprimary from the dns server configuration
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/autoprimaries"
    if is_autoprimary_present(uri, ctx, ip, nameserver):
        uri = (
            f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/autoprimaries/{ip}/{nameserver}"
        )
        r = utils.http_delete(uri, ctx)
        if r.status_code == 204:
            utils.exit_action(ctx, success=True, message=f"Autoprimary {ip}/{nameserver} deleted")
        else:
            utils.exit_action(ctx, success=False, message=f"Failed deleting {ip}/{nameserver}")
    utils.exit_action(ctx, success=True, message=f"Autoprimary {ip}/{nameserver} already absent")


@autoprimary.command("import")
@click.argument("file", type=click.File())
@click.option(
    "--replace",
    is_flag=True,
    help="Replace all old autoprimaries settings with new ones",
)
@click.option("--ignore-errors", is_flag=True, help="Continue import even when requests fail")
@click.pass_context
def autoprimary_import(ctx, file, replace, ignore_errors):
    """Import a list with your autoprimaries settings"""
    settings = utils.extract_file(file)
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/autoprimaries"
    upstream_settings = utils.read_settings_from_upstream(uri, ctx)
    utils.validate_simple_import(ctx, settings, upstream_settings, replace)
    if replace and upstream_settings:
        replace_autoprimary_import(uri, ctx, settings, upstream_settings, ignore_errors)
    else:
        for nameserver in settings:
            r = utils.http_post(uri, ctx, payload=nameserver)
            if not r.status_code == 201:
                ctx.obj.logger.error(f"Failed adding nameserver {nameserver}")
                if not ignore_errors:
                    utils.exit_action(
                        ctx,
                        success=False,
                        message=f"Failed adding nameserver {nameserver} and exiting early",
                    )
    utils.exit_action(ctx, success=True, message="Successfully added autoprimary configuration")


@autoprimary.command("list")
@click.pass_context
def autoprimary_list(ctx):
    """
    Lists all currently configured autoprimary servers
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/autoprimaries"
    r = utils.http_get(uri, ctx)
    if r.status_code == 200:
        utils.exit_action(ctx, success=True, response=r, print_data=True)
    else:
        utils.exit_action(ctx, success=False, message="Failed acquiring the list of autoprimaries")


@autoprimary.command("spec")
def autoprimary_spec():
    """Open the autoprimary specification on https://redocly.github.io"""

    utils.open_spec("autoprimary")


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
        True: If requested autoprimaries are already configured, otherwise False.
    """
    upstream_autoprimaries = utils.http_get(uri, ctx)
    if upstream_autoprimaries.status_code == 200:
        autoprimaries = upstream_autoprimaries.json()
        for primary in autoprimaries:
            if primary.get("nameserver") == nameserver and primary.get("ip") == ip:
                return True
    return False


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
            r = utils.http_post(uri, ctx, payload=nameserver)
            if r.status_code != 201:
                utils.handle_import_early_exit(
                    ctx, f"Failed adding nameserver {nameserver}", ignore_errors
                )
    for nameserver in upstreams_to_delete:
        r = utils.http_delete(f"{uri}/{nameserver['nameserver']}/{nameserver['ip']}", ctx)
        if not r.status_code == 204:
            utils.handle_import_early_exit(
                ctx, f"Failed deleting nameserver {nameserver}", ignore_errors
            )
