#!/usr/bin/env python3
"""
powerdns-cli: Manage PowerDNS Zones/Records
"""
import click
import requests

from .commands.autoprimary import autoprimary
from .commands.config import config
from .commands.cryptokey import cryptokey
from .commands.metadata import metadata
from .commands.network import network
from .commands.record import record
from .commands.tsigkey import tsigkey
from .commands.view import view
from .commands.zone import zone
from .utils import logger
from .utils import main as utils


# create click command group with 3 global options
@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "-a",
    "--apikey",
    help="Provide your apikey manually",
    type=click.STRING,
    default=None,
    required=True,
)
@click.option(
    "json_output",
    "-j",
    "--json",
    help="Use json output",
    is_flag=True,
)
@click.option("-u", "--url", help="DNS server api url", type=click.STRING, required=True)
@click.option(
    "-k",
    "--insecure",
    help="Accept unsigned or otherwise untrustworthy certificates",
    is_flag=True,
    show_default=True,
)
@click.option(
    "--skip-check",
    help="Skips the preflight request towards your apihost",
    is_flag=True,
)
@click.option(
    "-l",
    "--log-level",
    help="Set the log level",
    default="INFO",
    type=click.Choice(
        logger.LOG_LEVELS.keys(),
        case_sensitive=False,
    ),
)
@click.pass_context
def cli(ctx, apikey, json_output, url, insecure, skip_check, log_level):
    """Manage PowerDNS Authoritative Nameservers and their Zones/Records

    Your target server api must be specified through the corresponding cli-flags.
    You can also export them with the prefix POWERDNS_CLI_, for example:
    export POWERDNS_CLI_APIKEY=foobar
    """
    ctx.ensure_object()
    ctx.obj.config["apihost"] = url
    ctx.obj.config["key"] = apikey
    ctx.obj.config["json"] = json_output
    ctx.obj.config["log_level"] = log_level
    ctx.obj.logger.setLevel(logger.LOG_LEVELS[log_level])
    ctx.obj.logger.debug("Creating session object")
    session = requests.session()
    session.verify = not insecure
    session.headers = {"X-API-Key": ctx.obj.config["key"]}
    ctx.obj.session = session
    if not skip_check:
        ctx.obj.logger.debug("Performing preflight check and version detection")
        uri = f"{ctx.obj.config['apihost']}/api/v1/servers"
        preflight_request = utils.http_get(uri, ctx)
        if not preflight_request.status_code == 200:
            utils.print_output(
                {
                    "error": "No successful connection to sever, "
                    f"status code {preflight_request.status_code}"
                }
            )
            raise SystemExit(1)
        ctx.obj.config["major_version"] = int(
            [
                server["version"]
                for server in preflight_request.json()
                if server["id"] == "localhost"
            ][0].split(".")[0]
        )
        ctx.obj.logger.debug(f"Detected api version {ctx.obj.config['major_version']}")
    else:
        ctx.obj.logger.debug("Skipped preflight check and set api version to 4")
        ctx.obj.config["major_version"] = 4


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

    utils.print_output({"version": importlib.metadata.version("powerdns-cli")})


def main():
    """Main entrypoint to the cli application"""
    cli(auto_envvar_prefix="POWERDNS_CLI")


if __name__ == "__main__":
    main()
