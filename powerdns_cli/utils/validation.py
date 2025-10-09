"""
A collection of custom Click parameter types for DNS and IP validation.
The types are exposed as the following objects:
- PowerDNSZone
- AutoprimaryZone
- IPRange
- IPAddress

These objects can be directly used as click types, since they which already invoked the classes.

Usage:
    These types can be used as Click parameter types in CLI commands. For example:
        @click.argument("zone", type=PowerDNSZone)
        @click.argument("ip", type=IPAddress)
"""

import ipaddress
import re
from typing import Any

import click
import requests

from .logger import LOG_LEVELS
from .main import exit_action, http_get


class PowerDNSZoneType(click.ParamType):
    """Conversion class to ensure, that a provided string is a valid dns name"""

    name = "zone"

    def convert(self, value, param, ctx) -> str:
        if ctx is None:  # Graciously assume that users run the latest powerdns-version
            try:
                if not re.match(
                    r"^((?!-)[-A-Z\d]{1,63}(?<!-)[.])+(?!-)[-A-Z\d]{1,63}(?<!-)(\.|\.\.[\w_]+)?$",
                    value,
                    re.IGNORECASE,
                ):
                    raise click.BadParameter("You did not provide a valid zone name.")
            except (AttributeError, TypeError):
                self.fail(f"{value!r} couldn't be converted to a canonical zone", param, ctx)
        else:
            try:
                if ctx.obj.config.get("major_version", 4) >= 5 and not re.match(
                    r"^((?!-)[-A-Z\d]{1,63}(?<!-)[.])+(?!-)[-A-Z\d]{1,63}(?<!-)(\.|\.\.[\w_]+)?$",
                    value,
                    re.IGNORECASE,
                ):
                    raise click.BadParameter("You did not provide a valid zone name.")
                if ctx.obj.config.get("major_version", 4) <= 4 and not re.match(
                    r"^((?!-)[-A-Z\d]{1,63}(?<!-)[.])+(?!-)[-A-Z\d]{1,63}(?<!-)[.]?$",
                    value,
                    re.IGNORECASE,
                ):
                    raise click.BadParameter("You did not provide a valid zone name.")
            except (AttributeError, TypeError):
                self.fail(f"{value!r} couldn't be converted to a canonical zone", param, ctx)

        if not value.endswith(".") and ".." not in value:
            value += "."
        return value


PowerDNSZone = PowerDNSZoneType()


class AutoprimaryZoneType(click.ParamType):
    """Conversion class to ensure, that a provided string is a valid dns name"""

    name = "autoprimary_zone"

    def convert(self, value, param, ctx) -> str:
        try:
            if not re.match(
                r"^((?!-)[-A-Z\d]{1,63}(?<!-)[.])+(?!-)[-A-Z\d]{1,63}(?<!-)[.]?$",
                value,
                re.IGNORECASE,
            ):
                raise click.BadParameter("You did not provide a valid zone name.")
        except (AttributeError, TypeError):
            self.fail(f"{value!r} couldn't be converted to a canonical zone", param, ctx)

        return value.rstrip(".")


AutoprimaryZone = AutoprimaryZoneType()


class IPRangeType(click.ParamType):
    """Conversion class to ensure, that a provided string is a valid ip range"""

    name = "iprange"

    def convert(self, value, param, ctx) -> str:
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except (ValueError, ipaddress.AddressValueError):
            self.fail(f"{value!r} is no valid IP-address range", param, ctx)


IPRange = IPRangeType()


class IPAddressType(click.ParamType):
    """Conversion class to ensure, that a provided string is a valid ip range"""

    name = "ipaddress"

    def convert(self, value, param, ctx) -> str:
        try:
            return str(ipaddress.ip_address(value))
        except (ValueError, ipaddress.AddressValueError):
            self.fail(f"{value!r} is no valid IP-address", param, ctx)


IPAddress = IPAddressType()


class DefaultCommand(click.Command):
    """A command that automatically adds shared CLI arguments and sets up logging.

    This class extends click.Command to automatically add options for apikey, json output,
    server URL, insecure mode, preflight check skipping, and log level. It also configures
    logging and session objects before command invocation.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the command with additional common options.

        Args:
            *args: Positional arguments passed to click.Command.
            **kwargs: Keyword arguments passed to click.Command.
                     If 'params' is not provided, it will be initialized as an empty list.
        """
        # This shouldn't happen, but :shrug:
        if not kwargs.get("params"):
            kwargs["params"] = []
        kwargs["params"].append(
            click.Option(
                ["-a", "--apikey"],
                help="Provide your apikey manually",
                type=click.STRING,
                default=None,
                required=True,
            )
        )
        kwargs["params"].append(
            click.Option(
                ["json_output", "-j", "--json"],
                help="Use json output",
                is_flag=True,
            )
        )
        kwargs["params"].append(
            click.Option(
                ["-u", "--url"],
                help="DNS server api url",
                type=click.STRING,
                required=True,
            )
        )
        kwargs["params"].append(
            click.Option(
                ["-k", "--insecure"],
                help="Accept unsigned or otherwise untrustworthy certificates",
                is_flag=True,
                show_default=True,
            )
        )
        kwargs["params"].append(
            click.Option(
                ["--skip-check"],
                help="Skips the preflight request towards your apihost",
                is_flag=True,
            )
        )
        kwargs["params"].append(
            click.Option(
                ["-l", "--log-level"],
                help="Set the log level",
                default="INFO",
                type=click.Choice(
                    LOG_LEVELS.keys(),
                    case_sensitive=False,
                ),
            )
        )
        super().__init__(*args, **kwargs)

    def invoke(self, ctx: click.Context) -> None:
        """Invoke the command, setting up logging and session objects.

        Args:
            ctx: The click context object, containing command-line arguments and configuration.
        """
        if ctx.obj.config.get("pytest"):
            super().invoke(ctx)
        ctx.obj.config = {
            "apihost": ctx.params["url"],
            "key": ctx.params["apikey"],
            "json": ctx.params["json_output"],
            "log_level": ctx.params["log_level"],
            "skip_check": ctx.params["skip_check"],
            "insecure": ctx.params["insecure"],
        }
        ctx.obj.logger.setLevel(LOG_LEVELS[ctx.obj.config["log_level"]])
        ctx.obj.logger.debug("Creating session object")
        session = requests.session()
        session.verify = not ctx.obj.config["insecure"]
        session.headers = {"X-API-Key": ctx.obj.config["key"]}
        ctx.obj.session = session
        if not ctx.obj.config["skip_check"]:
            ctx.obj.logger.debug("Performing preflight check and version detection")
            uri = f"{ctx.obj.config['apihost']}/api/v1/servers"
            preflight_request = http_get(uri, ctx)
            if not preflight_request.status_code == 200:
                exit_action(ctx, False, "Failed to reach server for preflight request.")
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
        super().invoke(ctx)

        # try:
        #     super().invoke(ctx)
        # except click.ClickException:
        #     raise
