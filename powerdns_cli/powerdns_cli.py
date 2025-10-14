#!/usr/bin/env python3
"""
powerdns-cli: Manage PowerDNS Zones/Records
"""
import click

from powerdns_cli.utils.validation import ContextObj

from .commands.autoprimary import autoprimary
from .commands.config import config
from .commands.cryptokey import cryptokey
from .commands.metadata import metadata
from .commands.network import network
from .commands.record import record
from .commands.tsigkey import tsigkey
from .commands.view import view
from .commands.zone import zone


# create click command group with 3 global options
@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.pass_context
def cli(ctx):
    """Manage PowerDNS Authoritative Nameservers."""
    ctx.ensure_object(ContextObj)


cli.add_command(autoprimary)
cli.add_command(config)
cli.add_command(cryptokey)
cli.add_command(metadata)
cli.add_command(network)
cli.add_command(record)
cli.add_command(tsigkey)
cli.add_command(view)
cli.add_command(zone)


@cli.command("version")
def print_version():
    """Show the powerdns-cli version"""
    # pylint: disable-next=import-outside-toplevel
    import importlib

    click.echo(f"powerdns-cli version {importlib.metadata.version('powerdns-cli')}")


def main():
    """Main entrypoint to the cli application"""
    # pylint: disable-next=no-value-for-parameter
    cli()


if __name__ == "__main__":
    main()
