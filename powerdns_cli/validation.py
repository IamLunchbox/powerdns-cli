"""
validation.py

A collection of custom Click parameter types for DNS and IP validation.
The types are exposed as objects, which already invoked the classes:
- PowerDNSZone
- AutoprimaryZone
- IPRange
- IPAddress

These objects can be directly used as click types.

Usage:
    These types can be used as Click parameter types in CLI commands. For example:
        @click.argument("zone", type=PowerDNSZone)
        @click.argument("ip", type=IPAddress)
"""

import ipaddress
import re

import click


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
