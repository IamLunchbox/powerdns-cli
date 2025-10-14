"""A collection of custom Click parameter types for DNS and IP validation and classes.
The types are exposed as the following objects:
- AutoprimaryZone
- IPRange
- IPAddress
These objects can be directly used as Click types, since they are already invoked as classes.
Additionally, the DefaultCommand class provides command setup and default options to each command.
The ContextObj class provides a custom scaffold for the click.Context object.
Usage:
    These types can be used as Click parameter types in CLI commands. For example:
        @click.argument("ip", type=IPAddress)
"""

import ipaddress
import logging
import os.path
import re
from itertools import product
from pathlib import Path
from sys import version_info
from typing import Any, Callable, NamedTuple

import click
import requests
from platformdirs import user_config_path

from . import logger
from .main import exit_action, http_get

if version_info.minor < 11:
    import tomli as tomllib
else:
    import tomllib


class DefaultDictKey(NamedTuple):
    """
    NamedTuple class to annotate a tuple for easier indication of the usage of the tuple items.
    """

    ctx_key: str
    cli_key: str


DEFAULT_ARGS = {
    DefaultDictKey(ctx_key="apihost", cli_key="url"),
    DefaultDictKey(ctx_key="key", cli_key="apikey"),
    DefaultDictKey(ctx_key="json", cli_key="json"),
    DefaultDictKey(ctx_key="debug", cli_key="debug"),
    DefaultDictKey(ctx_key="insecure", cli_key="insecure"),
    DefaultDictKey(ctx_key="api_version", cli_key="api-version"),
}


def powerdns_zone(f: Callable[..., Any]) -> Callable[..., Any]:
    """
    Decorator to add a 'dns_zone' positional argument to a Click command.
    This decorator applies Click's `argument` decorator to the input function,
    adding a required positional argument named `dns_zone` of type `str`.
    This ensures that dns_zone is always correctly given as a parameter to enable
    the conversion in DefaultCommand.invoke().
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
    pdns5_regex = re.compile(
        r"^((?!-)[-A-Z\d]{1,63}(?<!-)[.])+(?!-)[-A-Z\d]{1,63}(?<!-)(\.|\.\.[\w_]+)?$",
        re.IGNORECASE,
    )
    pdns4_regex = re.compile(
        r"^((?!-)[-A-Z\d]{1,63}(?<!-)[.])+(?!-)[-A-Z\d]{1,63}(?<!-)[.]?$",
        re.IGNORECASE,
    )
    try:
        if ctx is None:
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
    if not value.endswith(".") and ".." not in value:
        value += "."
    return value


class AutoprimaryZoneType(click.ParamType):
    """Conversion class to ensure that a provided string is a valid DNS name."""

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


class IPRangeType(click.ParamType):
    """Conversion class to ensure that a provided string is a valid IP range."""

    name = "iprange"

    def convert(self, value, param, ctx) -> str:
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except (ValueError, ipaddress.AddressValueError):
            self.fail(f"{value!r} is no valid IP-address range", param, ctx)


class IPAddressType(click.ParamType):
    """Conversion class to ensure that a provided string is a valid IP address."""

    name = "ipaddress"

    def convert(self, value, param, ctx) -> str:
        try:
            return str(ipaddress.ip_address(value))
        except (ValueError, ipaddress.AddressValueError):
            self.fail(f"{value!r} is no valid IP-address", param, ctx)


# pylint: disable=invalid-name
IPAddress = IPAddressType()
AutoprimaryZone = AutoprimaryZoneType()
IPRange = IPRangeType()
# pylint: enable=invalid-name


class DefaultCommand(click.Command):
    """A command that automatically adds shared CLI arguments and sets up logging.
    This class extends click.Command to automatically add options for apikey, JSON output,
    server URL, insecure mode, preflight check skipping, and log level.
    It also configures logging and session objects before command invocation.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the command with additional common options.
        Args:
            *args: Positional arguments passed to click.Command.
            **kwargs: Keyword arguments passed to click.Command.
                     If 'params' is not provided, it will be initialized as an empty list.
        """
        if not kwargs.get("params"):
            kwargs["params"] = []
        kwargs["params"].append(
            click.Option(
                ["-a", "--apikey"],
                help="Provide your apikey manually.",
                type=click.STRING,
            )
        )
        kwargs["params"].append(
            click.Option(
                ["json_output", "-j", "--json"],
                help="Use JSON output.",
                is_flag=True,
            )
        )
        kwargs["params"].append(
            click.Option(
                ["-u", "--url"],
                help="DNS server API URL.",
                type=click.STRING,
            )
        )
        kwargs["params"].append(
            click.Option(
                ["-k", "--insecure"],
                help="Accept unsigned or otherwise untrustworthy certificates.",
                is_flag=True,
                show_default=True,
            )
        )
        kwargs["params"].append(
            click.Option(
                ["--api-version"], help="Manually set the API version.", type=click.Choice([4, 5])
            )
        )
        kwargs["params"].append(
            click.Option(["-d", "--debug"], help="Emit debug logs.", is_flag=True)
        )
        super().__init__(*args, **kwargs)

    def invoke(self, ctx: click.Context) -> None:
        """Invoke the command, setting up logging and session objects.
        Args:
            ctx: The Click context object, containing command-line arguments and configuration.
        """
        log_backlog = []
        if ctx.obj.config.get("pytest"):
            log_backlog.append("ctx.obj.config.pytest was 'True'.")
            if ctx.params.get("dns_zone"):
                log_backlog.append("dns_zone is set, validating.")
                ctx.params["dns_zone"] = validate_dns_zone(ctx, ctx.params["dns_zone"])
            log_backlog.append("Invoking click.Command.")
            super().invoke(ctx)
        DefaultCommand.parse_options(ctx, log_backlog)
        DefaultCommand.set_session_object(ctx)
        DefaultCommand.check_api_version(ctx)
        if ctx.params.get("dns_zone"):
            ctx.params["dns_zone"] = validate_dns_zone(ctx, ctx.params["dns_zone"])
        DefaultCommand.exit_on_incompatible_action(ctx)
        super().invoke(ctx)

    @staticmethod
    def exit_on_incompatible_action(ctx: click.Context) -> None:
        """Exit if the requested action is incompatible with the server's API version.
        API version <5 and actions "network" and "view" are checked.
        Args:
            ctx: A Click context object containing the logger and configuration.
        """
        if ctx.parent.info_name in ("network", "view") and ctx.obj.config["api_version"] < 5:
            error_message = (
                f"Your authoritative DNS server does not support {ctx.parent.info_name}s."
            )
            ctx.obj.logger.error(error_message)
            exit_action(ctx, success=False, message=error_message)

    @staticmethod
    def check_api_version(ctx: click.Context) -> None:
        """Detect or use the configured API version for the given context.
        Args:
            ctx: A Click context object containing the logger and configuration.
        Notes:
            If the API version is not set, it queries the server to detect the version.
            Exits with an error if the server is unreachable or the version cannot be detected.
        """
        if not ctx.obj.config["api_version"]:
            ctx.obj.logger.debug("API version unset, performing version detection.")
            uri = f"{ctx.obj.config['apihost']}/api/v1/servers"
            preflight_request = http_get(uri, ctx, log_body=False)
            if preflight_request.status_code != 200:
                exit_action(ctx, False, "Failed to reach server for version detection.")
            ctx.obj.config["api_version"] = int(
                next(
                    server["version"].split(".")[0]
                    for server in preflight_request.json()
                    if server["id"] == "localhost"
                )
            )
            ctx.obj.logger.debug(f"Detected API version {ctx.obj.config['api_version']}.")
        else:
            ctx.obj.logger.debug(
                f"Skipped version detection, API version is {ctx.obj.config['api_version']}."
            )

    @staticmethod
    def parse_options(ctx: click.Context, log_backlog: list) -> None:
        """Parse and set configuration options for the CLI context.
        Args:
            ctx: A Click context object containing parameters and a config object.
                Attributes are set by ContextObj.
        Notes:
            Skips preflight and object generation during unit tests.
            Loads additional configuration from a TOML file if present.
            Sets logger level based on the debug flag.
        """
        ctx.obj.config = {
            "apihost": ctx.params["url"],
            "api_version": ctx.params["api_version"],
            "debug": ctx.params["debug"],
            "key": ctx.params["apikey"],
            "insecure": ctx.params["insecure"],
            "json": ctx.params["json_output"],
        }
        configuration_file = identify_config_file()
        if configuration_file:
            log_backlog.append(f"Detected {configuration_file} as config.")
            with open(configuration_file, "rb") as f:
                fileconfig = tomllib.load(f)
                fileconfig = {key.lower(): value for key, value in fileconfig.items()}
            log_backlog.append(f"Configuration file parsed with contents: {fileconfig}.")
            for ctx_key, conf_key in DEFAULT_ARGS:
                if ctx.obj.config.get(ctx_key) is None and fileconfig.get(conf_key):
                    log_backlog.append(f"Replacing {ctx_key}:None with {fileconfig[conf_key]}.")
                    ctx.obj.config[ctx_key] = fileconfig[conf_key]
        ctx.obj.logger.setLevel(logging.DEBUG if ctx.obj.config["debug"] else logging.INFO)
        ctx.obj.logger.debug("Logger set up, logging items from backlog.")
        for log in log_backlog:
            ctx.obj.logger.debug(log)
        if not ctx.obj.config["key"] or not ctx.obj.config["apihost"]:
            error_msg = (
                f"Option '--{'apikey' if not ctx.obj.config['key'] else 'url'}' is missing, "
                "provide it through the CLI, environment, or configuration file."
            )
            ctx.obj.logger.error(error_msg)
            exit_action(ctx, False, error_msg)

    @staticmethod
    def set_session_object(ctx: click.Context) -> None:
        """Initialize and configure a requests session object for the given context."""
        ctx.obj.logger.debug("Creating session object.")
        session = requests.session()
        session.verify = not ctx.obj.config["insecure"]
        session.headers = {"X-API-Key": ctx.obj.config["key"]}
        ctx.obj.session = session


# pylint: disable=too-few-public-methods
class ContextObj:
    """A context object for managing logging, configuration, and session state.
    Attributes:
        handler: A custom logging handler for collecting logs and results.
        logger: A logger instance for emitting log messages.
        config: A dictionary for storing configuration settings.
        session: A placeholder for a session object, initially None.
    """

    def __init__(self) -> None:
        """Initializes the ContextObj with a logger, handler, and default configuration."""
        self.handler = logger.ResultHandler()
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        self.handler.setFormatter(formatter)
        self.logger = logging.getLogger("cli_logger")
        self.logger.addHandler(self.handler)
        self.logger.setLevel(logging.INFO)
        self.config: dict[str, Any] = {}
        self.session: requests.Session | None = None


# pylint: enable=too-few-public-methods


def identify_config_file() -> Path | None:
    """
    Identifies and returns the path to the first found PowerDNS CLI configuration file.
    Searches for configuration files in standard user config paths and the user's home directory.
    The function checks for the following file patterns:
    - In user config directories (for appnames "powerdns-cli" and "powerdns_cli"):
        - config.toml
        - configuration.toml
    - In the user's home directory:
        - powerdns-cli.conf
    Returns:
        Path | None: The path to the first found configuration file, or None if none is found.
    """
    app_titles = (
        user_config_path(appname="powerdns-cli"),
        user_config_path(appname="powerdns_cli"),
    )
    config_files = ("config.toml", "configuration.toml")
    filepaths = list(product(app_titles, config_files))
    filepaths.extend(
        [
            (Path(os.environ["HOME"]), ".powerdns-cli.conf"),
            (Path(os.environ["HOME"]), ".powerdns_cli.conf"),
        ]
    )
    for directory, name in filepaths:
        if os.path.isfile(directory / name):
            return directory / name
    return None
