"""
A Click-based CLI module for managing autoprimary DNS server configurations.

This module provides commands to add and manage autoprimary upstream DNS servers.

Commands:
    add: Adds a new autoprimary upstream DNS server with the specified IP and nameserver.
"""

import click

from . import utils
from .validation import AutoprimaryZone, IPAddress


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
    exit_if_autoprimary_present(uri, ctx, ip, nameserver)
    r = utils.http_post(uri, ctx, payload)
    ctx.obj.handler.set_response_data(r, ctx)
    if r.status_code == 201:
        ctx.obj.handler.set_message(f"Autoprimary {ip} with nameserver {nameserver} added")
        ctx.obj.handler.set_success()
        utils.exit_cli(ctx, 0)
    else:
        ctx.obj.handler.set_message(f"Failed adding {ip} with nameserver {nameserver}")
        ctx.obj.handler.set_success(False)
        utils.exit_cli(ctx, 1)


def exit_if_autoprimary_present(uri: str, ctx: click.Context, ip: str, nameserver: str) -> None:
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
        SystemExit: If requested autoprimaries are already configured, otherwise None.
    """
    upstream_autoprimaries = utils.http_get(uri, ctx)
    if upstream_autoprimaries.status_code == 200:
        autoprimaries = upstream_autoprimaries.json()
        for primary in autoprimaries:
            if primary.get("nameserver") == nameserver and primary.get("ip") == ip:
                ctx.obj.handler.set_message(
                    f"Autoprimary {ip} with nameserver {nameserver} already present"
                )
                ctx.obj.handler.set_success()
