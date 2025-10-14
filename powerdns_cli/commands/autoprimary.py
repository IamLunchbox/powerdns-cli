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
from ..utils.validation import AutoprimaryZone, DefaultCommand, IPAddress


@click.group()
def autoprimary():
    """Change autoprimaries, which may modify this server.
    Autoprimaries may automatically provision their secondaries with notifications.
    To edit the configured autoprimaries, these actions may be used.
    Additionally, autosecondary support must be enabled within a zone and other requirements must be
    met. Check the documentation here:
    https://doc.powerdns.com/authoritative/modes-of-operation.html.
    """


@autoprimary.command(
    "add",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.argument("ip", type=IPAddress)
@click.argument("nameserver", type=AutoprimaryZone)
@click.option("--account", default="", type=click.STRING, help="Option")
@click.pass_context
def autoprimary_add(ctx, ip, nameserver, account, **kwargs):
    """
    Adds an autoprimary upstream DNS server.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/autoprimaries"
    payload = {"ip": ip, "nameserver": nameserver, "account": account}
    ctx.obj.logger.info(f"Attempting to add autoprimary {ip}/{nameserver}.")
    if is_autoprimary_present(uri, ctx, ip, nameserver):
        ctx.obj.logger.info(f"Autoprimary {ip}/{nameserver} already present.")
        utils.exit_action(
            ctx,
            success=True,
            message=f"Autoprimary {ip} with nameserver {nameserver} already present.",
        )
    ctx.obj.logger.debug(f"Sending POST request for {ip}/{nameserver}.")
    r = utils.http_post(uri, ctx, payload)
    if r.status_code == 201:
        ctx.obj.logger.info(f"Successfully added autoprimary {ip}/{nameserver}.")
        utils.exit_action(ctx, success=True, message=f"Autoprimary {ip}/{nameserver} added.")
    else:
        ctx.obj.logger.error(f"Failed to add {ip}/{nameserver}.")
        utils.exit_action(ctx, success=False, message=f"Failed adding {ip}/{nameserver}.")


@autoprimary.command(
    "delete",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.argument("ip", type=IPAddress)
@click.argument("nameserver", type=AutoprimaryZone)
@click.pass_context
def autoprimary_delete(ctx, ip, nameserver, **kwargs):
    """
    Deletes an autoprimary from the DNS server configuration.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/autoprimaries"
    ctx.obj.logger.info(f"Attempting to delete autoprimary {ip}/{nameserver}.")
    if is_autoprimary_present(uri, ctx, ip, nameserver):
        uri = (
            f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/autoprimaries/{ip}/{nameserver}"
        )
        ctx.obj.logger.debug(f"Sending delete request for {ip}/{nameserver}.")
        r = utils.http_delete(uri, ctx)
        if r.status_code == 204:
            ctx.obj.logger.info(f"Successfully deleted autoprimary {ip}/{nameserver}.")
            utils.exit_action(ctx, success=True, message=f"Autoprimary {ip}/{nameserver} deleted.")
        else:
            ctx.obj.logger.error(f"Failed to delete {ip}/{nameserver}: HTTP {r.status_code}.")
            utils.exit_action(ctx, success=False, message=f"Failed deleting {ip}/{nameserver}.")
    else:
        ctx.obj.logger.info(f"Autoprimary {ip}/{nameserver} already absent.")
        utils.exit_action(
            ctx, success=True, message=f"Autoprimary {ip}/{nameserver} already absent."
        )


@autoprimary.command(
    "import",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.argument("file", type=click.File())
@click.option(
    "--replace",
    is_flag=True,
    help="Replace all old autoprimaries settings with new ones",
)
@click.option("--ignore-errors", is_flag=True, help="Continue import even when requests fail")
@click.pass_context
def autoprimary_import(ctx, file, replace, ignore_errors, **kwargs):
    """Import a list with your autoprimaries settings.
    File format:
    [{"ip": str, "nameserver": "str}, ...]
    """
    ctx.obj.logger.info("Starting autoprimary import process.")
    settings = utils.extract_file(ctx, file)
    ctx.obj.logger.debug(f"Extracted {len(settings)} settings from file.")
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/autoprimaries"
    upstream_settings = utils.read_settings_from_upstream(uri, ctx)
    ctx.obj.logger.debug(f"Fetched {len(upstream_settings)} upstream settings.")
    utils.validate_simple_import(ctx, settings, upstream_settings, replace)
    if replace and upstream_settings:
        ctx.obj.logger.info("Replacing existing autoprimary settings.")
        replace_autoprimary_import(uri, ctx, settings, upstream_settings, ignore_errors)
    else:
        ctx.obj.logger.info("Adding new autoprimary settings.")
        for nameserver in settings:
            ctx.obj.logger.debug(f"Adding nameserver: {nameserver}.")
            r = utils.http_post(uri, ctx, payload=nameserver)
            if not r.status_code == 201:
                ctx.obj.logger.error(f"Failed adding nameserver {nameserver}.")
                if not ignore_errors:
                    utils.exit_action(
                        ctx,
                        success=False,
                        message=f"Failed adding nameserver {nameserver} and exiting early.",
                    )
    ctx.obj.logger.info("Successfully added autoprimary configuration.")
    utils.exit_action(ctx, success=True, message="Successfully added autoprimary configuration.")


@autoprimary.command(
    "list", cls=DefaultCommand, context_settings={"auto_envvar_prefix": "POWERDNS_CLI"}
)
@click.pass_context
def autoprimary_list(ctx, **kwargs):
    """
    Lists all currently configured autoprimary servers.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/autoprimaries"
    utils.show_setting(ctx, uri, "autoprimary", "list")


@autoprimary.command("spec")
def autoprimary_spec():
    """Open the autoprimary specification on https://redocly.github.io."""
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
        bool: If requested autoprimaries are already configured, otherwise False.
    """
    ctx.obj.logger.debug(
        f"Checking if autoprimary (IP: {ip}, nameserver: {nameserver}) is already present."
    )
    upstream_autoprimaries = utils.http_get(uri, ctx)
    if upstream_autoprimaries.status_code == 200:
        autoprimaries = upstream_autoprimaries.json()
        ctx.obj.logger.debug(f"Found {len(autoprimaries)} autoprimary entries to check.")
        for primary in autoprimaries:
            if primary.get("nameserver") == nameserver and primary.get("ip") == ip:
                ctx.obj.logger.info(
                    f"Autoprimary (IP: {ip}, nameserver: {nameserver}) already exists."
                )
                return True
    ctx.obj.logger.debug("No matching autoprimary found.")
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
    ctx.obj.logger.debug(
        f"Comparing {len(settings)} desired settings with {len(upstream_settings)} "
        f"upstream settings."
    )
    for nameserver in upstream_settings:
        if nameserver in settings:
            existing_upstreams.append(nameserver)
        else:
            upstreams_to_delete.append(nameserver)
    ctx.obj.logger.debug(
        f"Found {len(existing_upstreams)} existing and {len(upstreams_to_delete)} "
        f"obsolete upstreams."
    )
    for nameserver in settings:
        if nameserver not in existing_upstreams:
            ctx.obj.logger.info(f"Adding new nameserver: {nameserver}.")
            r = utils.http_post(uri, ctx, payload=nameserver)
            if r.status_code != 201:
                ctx.obj.logger.error(
                    f"Failed to add nameserver {nameserver}: HTTP {r.status_code}."
                )
                handle_import_early_exit(
                    ctx, f"Failed adding nameserver {nameserver}", ignore_errors
                )
    for nameserver in upstreams_to_delete:
        ctx.obj.logger.info(f"Deleting obsolete nameserver: {nameserver}.")
        r = utils.http_delete(f"{uri}/{nameserver['nameserver']}/{nameserver['ip']}", ctx)
        if not r.status_code == 204:
            ctx.obj.logger.error(f"Failed to delete nameserver {nameserver}: HTTP {r.status_code}.")
            handle_import_early_exit(ctx, f"Failed deleting nameserver {nameserver}", ignore_errors)
    ctx.obj.logger.info("Autoprimary import replacement completed.")


def handle_import_early_exit(ctx: click.Context, message: str, ignore_errors: bool) -> None:
    """
    Handle import errors with configurable behavior based on ignore_errors flag.
    When ignore_errors is False (strict mode):
    - Prints error to stdout and exits immediately with code 1.
    - Stops all further processing.
    When ignore_errors is True (permissive mode):
    - Logs error but continues execution.
    - Allows processing of remaining items.

    Args:
        ctx: Click context object.
        message: Dictionary containing error information (typically with 'error' key).
        ignore_errors: If True, log error and continue; if False, log error and exit.
    """
    if ignore_errors:
        ctx.obj.logger.error(message)
    else:
        ctx.obj.handler.set_message(message)
        ctx.obj.handler.set_failed()
        utils.exit_cli(ctx)
