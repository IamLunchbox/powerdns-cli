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
import logging
import re
from typing import Any, Callable

import click
import requests

from .main import exit_action, http_get


def powerdns_zone(f: Callable[..., Any]) -> Callable[..., Any]:
    """
    Decorator to add a 'dns_zone' positional argument to a Click command.

    This decorator applies Click's `argument` decorator to the input function,
    adding a required positional argument named `dns_zone` of type `str`.
    This shall ensure, that dns_zone is always correctly given as a parameter to enable
    the coversion in DefaultCommand.invoke().

    Args:
        f (Callable[..., Any]): The Click command function to decorate.

    Returns:
        Callable[..., Any]: The decorated function with the `dns_zone` argument added.

    Example:
        >>> @click.command()
        >>> @powerdns_zone
        >>> def my_command(dns_zone: str):
        ...     click.echo(f"DNS Zone: {dns_zone}")
        ...
        >>> my_command()
        # Usage: my_command example.com
    """
    return click.argument("dns_zone", type=str, metavar="zone")(f)


def validate_dns_zone(ctx: click.Context, value: str) -> str:
    """
    Validate a DNS zone name according to PowerDNS version-specific rules.

    This function checks if the provided zone name is valid for the PowerDNS API version
    specified in the context. If no context is provided, it defaults to the latest version's rules.

    Args:
        ctx (click.Context): The Click context, which may contain the PowerDNS major version.
                                       If `None`, the latest version's rules are applied.
        value (str): The DNS zone name to validate.

    Returns:
        str: The validated and canonicalized zone name (ensures it ends with a dot).

    Raises:
        click.BadParameter: If the zone name is invalid for the specified PowerDNS version.

    Examples:
        >>> validate_dns_zone(None, "example.com")
        'example.com.'
        >>> validate_dns_zone(ctx, "example.com..custom")
        'example.com..custom'
    """
    # Regex for PowerDNS >= 5
    pdns5_regex = re.compile(
        r"^((?!-)[-A-Z\d]{1,63}(?<!-)[.])+(?!-)[-A-Z\d]{1,63}(?<!-)(\.|\.\.[\w_]+)?$",
        re.IGNORECASE,
    )
    # Regex for PowerDNS <= 4
    pdns4_regex = re.compile(
        r"^((?!-)[-A-Z\d]{1,63}(?<!-)[.])+(?!-)[-A-Z\d]{1,63}(?<!-)[.]?$",
        re.IGNORECASE,
    )
    try:
        if ctx is None:  # Assume latest version if no context
            if not pdns5_regex.match(value):
                raise click.BadParameter("You did not provide a valid zone name.")
        else:
            api_version = ctx.obj.config.get("api_version", 4)
            if api_version >= 5 and not pdns5_regex.match(value):
                raise click.BadParameter("You did not provide a valid zone name.")
            if api_version <= 4 and not pdns4_regex.match(value):
                raise click.BadParameter("You did not provide a valid zone name.")
    except (AttributeError, TypeError) as e:
        raise click.BadParameter(f"{value!r} couldn't be converted to a canonical zone", ctx) from e

    # Ensure the zone name ends with a dot (unless it's a relative zone)
    if not value.endswith(".") and ".." not in value:
        value += "."
    return value


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
                ["--api-version"], help="Manually set the API version", type=click.Choice([4, 5])
            )
        )
        kwargs["params"].append(
            click.Option(["-d", "--debug"], help="Emit debug logs", is_flag=True)
        )
        super().__init__(*args, **kwargs)

    def invoke(self, ctx: click.Context) -> None:
        """Invoke the command, setting up logging and session objects.

        Args:
            ctx: The click context object, containing command-line arguments and configuration.
        """
        # skip preflight request and object generation when unit tests run, they are preseeded
        # by a custom context object
        if ctx.obj.config.get("pytest"):
            if ctx.params.get("dns_zone"):
                ctx.params["dns_zone"] = validate_dns_zone(ctx, ctx.params["dns_zone"])
            super().invoke(ctx)
        ctx.obj.config = {
            "apihost": ctx.params["url"],
            "key": ctx.params["apikey"],
            "json": ctx.params["json_output"],
            "debug": ctx.params["debug"],
            "insecure": ctx.params["insecure"],
            "api_version": ctx.params["api_version"],
        }
        if ctx.params["debug"]:
            ctx.obj.logger.setLevel(logging.DEBUG)
        else:
            ctx.obj.logger.setLevel(logging.INFO)
        ctx.obj.logger.debug("Creating session object")
        session = requests.session()
        session.verify = not ctx.obj.config["insecure"]
        session.headers = {"X-API-Key": ctx.obj.config["key"]}
        ctx.obj.session = session
        if not ctx.obj.config["api_version"]:
            ctx.obj.logger.debug("Performing preflight check and version detection")
            uri = f"{ctx.obj.config['apihost']}/api/v1/servers"
            preflight_request = http_get(uri, ctx)
            if not preflight_request.status_code == 200:
                exit_action(ctx, False, "Failed to reach server for preflight request.")
            ctx.obj.config["api_version"] = int(
                [
                    server["version"]
                    for server in preflight_request.json()
                    if server["id"] == "localhost"
                ][0].split(".")[0]
            )
            ctx.obj.logger.debug(f"Detected api version {ctx.obj.config['api_version']}")
        else:
            ctx.obj.logger.debug(
                f"Skipped preflight check and set api version to {ctx.obj.config["api_version"]}"
            )
        if ctx.params.get("dns_zone"):
            ctx.params["dns_zone"] = validate_dns_zone(ctx, ctx.params["dns_zone"])
        super().invoke(ctx)

        # try:
        #     super().invoke(ctx)
        # except click.ClickException:
        #     raise
