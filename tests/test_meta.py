import click
import pytest

from powerdns_cli.utils.validation import PowerDNSZoneType


def test_valid_zone():
    testzone = PowerDNSZoneType()
    canonical_zone = testzone.convert("example.com.", None, None)
    converted_zone = testzone.convert("example.com", None, None)
    assert converted_zone == "example.com."
    assert canonical_zone == "example.com."


def test_invalid_zone():
    testzone = PowerDNSZoneType()
    for bad_zone in ("-example.com.", "example.com..", "^example.com.", "example"):
        with pytest.raises(click.BadParameter):
            testzone.convert(bad_zone, None, None)
