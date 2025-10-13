"""
A Click-based CLI module for managing and querying PowerDNS server configuration and statistics.

This module provides commands to export, list, and view operational statistics of a PowerDNS
server instance.

Commands:
    export: Retrieves and displays the current configuration of the PowerDNS instance.
    list: Lists all configured DNS servers.
    stats: Displays operational statistics of the DNS server.
    spec: Opens the configuration API specification in the browser.
"""

from typing import NoReturn

import click

from ..utils import main as utils
from ..utils.validation import DefaultCommand


@click.group()
def config():
    """Show servers and their configuration"""


@config.command(
    "export",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
)
@click.pass_context
def config_export(ctx: click.Context, **kwargs: dict) -> NoReturn:
    """
    Exports the configuration of this PowerDNS instance.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/config"

    ctx.obj.logger.info("Attempting to export PowerDNS configuration.")

    r = utils.http_get(uri, ctx)
    if r.status_code == 200:
        ctx.obj.logger.info("Successfully obtained configuration export.")
        utils.exit_action(
            ctx,
            success=True,
            message="Successfully obtained configuration export.",
            print_data=True,
            response=r,
        )
    else:
        ctx.obj.logger.error("Failed to obtain configuration export.")
        utils.exit_action(
            ctx,
            success=False,
            message="Failed obtaining a configuration export.",
            response=r,
        )


@config.command(
    "list",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
)
@click.pass_context
def config_list(ctx: click.Context, **kwargs: dict) -> NoReturn:
    """
    Lists configured DNS servers.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers"

    ctx.obj.logger.info("Attempting to list configured DNS servers.")

    r = utils.http_get(uri, ctx)
    if r.status_code == 200:
        ctx.obj.logger.info("Successfully listed configured DNS servers.")
        utils.exit_action(
            ctx,
            success=True,
            message="Successfully listed configured DNS servers.",
            print_data=True,
            response=r,
        )
    else:
        ctx.obj.logger.error("Failed to list DNS servers.")
        utils.exit_action(
            ctx,
            success=False,
            message="Failed listing servers.",
            response=r,
        )


@config.command(
    "stats",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
)
@click.pass_context
def config_stats(ctx: click.Context, **kwargs: dict) -> NoReturn:
    """
    Displays operational statistics of the DNS server.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/statistics"

    ctx.obj.logger.info("Attempting to query DNS server statistics.")

    r = utils.http_get(uri, ctx)
    if r.status_code == 200:
        ctx.obj.logger.info("Successfully queried DNS server statistics.")
        utils.exit_action(
            ctx,
            success=True,
            message="Successfully queried statistics.",
            print_data=True,
            response=r,
        )
    else:
        ctx.obj.logger.error("Failed to query DNS server statistics.")
        utils.exit_action(
            ctx,
            success=False,
            message="Failed querying statistics.",
            response=r,
        )


@config.command("spec")
def config_spec():
    """Open the config specification on https://redocly.github.io"""

    utils.open_spec("config")
