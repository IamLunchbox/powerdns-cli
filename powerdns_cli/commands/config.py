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

import click

from ..utils import main as utils
from ..utils.validation import DefaultCommand


@click.group()
def config():
    """Overall server configuration"""


@config.command(
    "export",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
)
@click.pass_context
def config_export(ctx, *args, **kwargs):
    """
    Query the configuration of this PowerDNS instance
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/config"
    r = utils.http_get(uri, ctx)
    if r.status_code == 200:
        utils.exit_action(
            ctx,
            message="Successfully obtained configuration export.",
            success=True,
            print_data=True,
            response=r,
        )
    utils.exit_action(ctx, success=False, message="Failed obtaining a configuration export.")


@config.command(
    "list",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
)
@click.pass_context
def config_list(ctx, *args, **kwargs):
    """
    Lists configured dns-servers
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers"
    r = utils.http_get(uri, ctx)
    if r.status_code == 200:
        utils.exit_action(
            ctx,
            message="Successfully listed configured dns-servers.",
            success=True,
            print_data=True,
            response=r,
        )
    utils.exit_action(ctx, success=False, message="Failed listing servers.", response=r)


@config.command(
    "stats",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
)
@click.pass_context
def config_stats(ctx, *args, **kwargs):
    """
    Displays operational statistics of your dns server
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/statistics"
    r = utils.http_get(uri, ctx)
    if r.status_code == 200:
        utils.exit_action(
            ctx,
            message="Successfully queried statistics.",
            success=True,
            print_data=True,
            response=r,
        )
    utils.exit_action(ctx, success=False, message="Failed querying statistics.", response=r)


@config.command("spec")
def config_spec():
    """Open the config specification on https://redocly.github.io"""

    utils.open_spec("config")
