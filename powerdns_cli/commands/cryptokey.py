"""
A Click-based CLI module for managing DNS cryptokeys in PowerDNS.

This module provides commands for managing DNSSEC cryptokeys.

Commands:
    add: Adds a new cryptokey to a DNS zone.
    delete: Deletes a cryptokey from a DNS zone.
    enable: Enables an existing cryptokey.
    disable: Disables an existing cryptokey.
    publish: Publishes an existing cryptokey.
    unpublish: Unpublishes an existing cryptokey.
    import: Imports a cryptokey using a private key.
    export: Exports a cryptokey, including the private key.
    list: Lists all cryptokeys for a DNS zone.
    spec: Opens the cryptokey API specification in the browser.
"""

import click
import requests

from ..utils import main as utils
from ..utils.validation import PowerDNSZone


@click.group()
def cryptokey():
    """Configure cryptokeys"""


@cryptokey.command("add")
@click.argument("key-type", type=click.Choice(["ksk", "zsk"]))
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.option(
    "-a",
    "--active",
    is_flag=True,
    default=False,
    help="Sets the key to active immediately",
)
@click.option("-p", "--publish", is_flag=True, default=False, help="Sets the key to published")
@click.option("--bits", type=click.INT, help="Set the key size in bits, required for zsk")
@click.option(
    "--algorithm",
    type=click.Choice(["rsasha1", "rsasha256", "rsasha512", "ecdsap256sha256", "ed25519", "ed448"]),
    help="Set the key size in bits, required for zsk",
)
@click.pass_context
def cryptokey_add(ctx, key_type, dns_zone, active, publish, bits, algorithm):
    """
    Adds a cryptokey to the zone. Is disabled and not published by default.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys"
    payload = {"active": active, "published": publish, "keytype": key_type}
    # Click CLI escapes newline characters
    for key, val in {"bits": bits, "algorithm": algorithm}.items():
        if val:
            payload[key] = val
    r = utils.http_post(uri, ctx, payload)

    if r.status_code == 201:
        ctx.obj.handler.set_success()
        ctx.obj.handler.set_data(r)
        utils.exit_cli(ctx, print_data=True)
    else:
        ctx.obj.handler.set_failed()
        ctx.obj.handler.set_message("Failed creating the dnssec-key")
        utils.exit_cli(ctx)


@cryptokey.command("delete")
@click.pass_context
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.argument("cryptokey-id", type=click.INT)
def cryptokey_delete(ctx, dns_zone, cryptokey_id):
    """
    Deletes the given cryptokey-id from all the configured cryptokeys
    """
    uri = (
        f"{ctx.obj.config['apihost']}"
        f"/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys/{cryptokey_id}"
    )
    does_cryptokey_exist(uri, f"Cryptokey with id {cryptokey_id} already absent", 0, ctx)
    r = utils.http_delete(uri, ctx)
    if r.status_code == 204:
        ctx.obj.handler.set_success()
        ctx.obj.handler.set_message(f"Deleted id '{cryptokey_id}' for '{dns_zone}'")
        utils.exit_cli(ctx, print_data=True)
    else:
        ctx.obj.handler.set_failed()
        ctx.obj.handler.set_message(f"Failed to delete id '{cryptokey_id}' for '{dns_zone}'")
        utils.exit_cli(ctx)


@cryptokey.command("disable")
@click.pass_context
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.argument("cryptokey-id", type=click.INT)
def cryptokey_disable(ctx, dns_zone, cryptokey_id):
    """
    Disables the cryptokey for this zone.
    """
    uri = (
        f"{ctx.obj.config['apihost']}"
        f"/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys/{cryptokey_id}"
    )
    payload = {
        "id": cryptokey_id,
        "active": False,
    }
    r = does_cryptokey_exist(uri, f"Cryptokey with id {cryptokey_id} does not exist", 1, ctx)
    if not r.json()["active"]:
        utils.print_output({"message": f"Cryptokey with id {cryptokey_id} is already inactive"})
        raise SystemExit(0)
    r = utils.http_put(uri, ctx, payload)
    if utils.create_output(
        r,
        (204,),
        optional_json={"message": f"Disabled id {cryptokey_id} for {dns_zone}"},
    ):
        raise SystemExit(0)
    raise SystemExit(1)


@cryptokey.command("enable")
@click.pass_context
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.argument("cryptokey-id", type=click.INT)
def cryptokey_enable(ctx, dns_zone, cryptokey_id):
    """
    Enables an already existing cryptokey
    """
    uri = (
        f"{ctx.obj.config['apihost']}"
        f"/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys/{cryptokey_id}"
    )
    payload = {
        "id": cryptokey_id,
        "active": True,
    }
    r = does_cryptokey_exist(uri, f"Cryptokey with id {cryptokey_id} does not exist", 1, ctx)
    if r.json()["active"]:
        utils.print_output({"message": f"Cryptokey with id {cryptokey_id} is already active"})
        raise SystemExit(0)
    r = utils.http_put(uri, ctx, payload)
    if utils.create_output(
        r,
        (204,),
        optional_json={"message": f"Enabled id {cryptokey_id} for {dns_zone}"},
    ):
        raise SystemExit(0)
    raise SystemExit(1)


@cryptokey.command("export")
@click.pass_context
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.argument("cryptokey-id", type=click.STRING)
def cryptokey_export(ctx, dns_zone, cryptokey_id):
    """
    Exports the cryptokey with the given id including the private key
    """
    uri = (
        f"{ctx.obj.config['apihost']}"
        f"/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys/{cryptokey_id}"
    )
    does_cryptokey_exist(uri, f"Cryptokey with id {cryptokey_id} does not exist", 1, ctx)
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@cryptokey.command("import")
@click.argument("key-type", type=click.Choice(["ksk", "zsk"]))
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.argument("private-key", type=click.STRING)
@click.option(
    "-a",
    "--active",
    is_flag=True,
    default=False,
    help="Sets the key to active immediately",
)
@click.option("-p", "--publish", is_flag=True, default=False, help="Sets the key to published")
@click.pass_context
def cryptokey_import(
    ctx,
    dns_zone,
    key_type,
    private_key,
    active,
    publish,
):
    """
    Adds a cryptokey to the zone. Is disabled and not published by default.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys"
    # Click CLI escapes newline characters
    secret = private_key.replace("\\n", "\n")
    payload = {
        "active": active,
        "published": publish,
        "privatekey": secret,
        "keytype": key_type,
    }
    if is_dnssec_key_present(uri, secret, ctx):
        utils.print_output({"message": "The provided dnssec-key is already present at the backend"})
        raise SystemExit(0)
    r = utils.http_post(uri, ctx, payload)
    if r.status_code == 201:
        ctx.obj.handler.set_success()
        ctx.obj.handler.set_data(r)
        utils.exit_cli(ctx, print_data=True)
    else:
        ctx.obj.handler.set_failed()
        ctx.obj.handler.set_message("Failed importing the provided dnssec-key")
        utils.exit_cli(ctx)


@cryptokey.command("list")
@click.pass_context
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
def cryptokey_list(ctx, dns_zone):
    """
    Lists all currently configured cryptokeys for this zone without displaying secrets
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@cryptokey.command("publish")
@click.pass_context
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.argument("cryptokey-id", type=click.INT)
def cryptokey_publish(ctx, dns_zone, cryptokey_id):
    """
    Publishes an already existing cryptokey. Implies activating it as well.
    """
    uri = (
        f"{ctx.obj.config['apihost']}"
        f"/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys/{cryptokey_id}"
    )
    payload = {
        "id": cryptokey_id,
        "published": True,
    }
    r = does_cryptokey_exist(uri, f"Cryptokey with id {cryptokey_id} does not exist", 1, ctx)
    if r.json()["published"]:
        utils.print_output({"message": f"Cryptokey with id {cryptokey_id} already published"})
        raise SystemExit(0)
    payload["active"] = r.json()["active"]
    r = utils.http_put(uri, ctx, payload)
    if utils.create_output(
        r,
        (204,),
        optional_json={"message": f"Published id {cryptokey_id} for {dns_zone}"},
    ):
        raise SystemExit(0)
    raise SystemExit(1)


@cryptokey.command("spec")
def cryptokey_spec():
    """Open the cryptokey specification on https://redocly.github.io"""

    utils.open_spec("cryptokey")


@cryptokey.command("unpublish")
@click.pass_context
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.argument("cryptokey-id", type=click.INT)
def cryptokey_unpublish(ctx, dns_zone, cryptokey_id):
    """
    Unpublishes an already existing cryptokey
    """
    uri = (
        f"{ctx.obj.config['apihost']}"
        f"/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys/{cryptokey_id}"
    )
    payload = {
        "id": cryptokey_id,
        "published": False,
    }
    r = does_cryptokey_exist(uri, f"Cryptokey with id {cryptokey_id} does not exist", 1, ctx)
    if not r.json()["published"]:
        utils.print_output({"message": f"Cryptokey with id {cryptokey_id} is already unpublished"})
        raise SystemExit(0)
    payload["active"] = r.json()["active"]
    r = utils.http_put(uri, ctx, payload)
    if utils.create_output(
        r,
        (204,),
        optional_json={"message": f"Unpublished id {cryptokey_id} for {dns_zone}"},
    ):
        raise SystemExit(0)
    raise SystemExit(1)


def import_cryptokey_pubkeys(
    uri: str,
    ctx: click.Context,
    new_settings: dict,
) -> dict | list:
    """Passes the given dictionary or list to the specified URI.

    Args:
        uri: The endpoint to send the settings to.
        ctx: Context object for HTTP requests.
        new_settings: The new settings to import (dict or list).

    Returns:
        dict | list: The updated settings.

    Raises:
        SystemExit: If settings already exist and neither merge nor replace is requested,
                   or if the nested key does not exist.
    """
    upstream_settings: list = utils.read_settings_from_upstream(uri, ctx)
    # Check for conflicts or early exit
    if new_settings in upstream_settings:
        utils.print_output({"message": "Your setting is already present"})
        raise SystemExit(0)

    # Prepare payload
    payload = new_settings

    return payload


def is_dnssec_key_present(uri: str, secret: str, ctx: click.Context) -> bool:
    """Retrieves all private keys for the given zone and checks if the private key is corresponding
    to the private key provided by the user"""
    # Powerdns will accept secrets without trailing newlines and actually appends one by itself -
    # and it will fix upper/lowercase in non-secret data
    secret = secret.rstrip("\n")
    secret = lowercase_secret(secret)
    present_keys = utils.http_get(uri, ctx)
    return any(
        secret
        == lowercase_secret(
            utils.http_get(f"{uri}/{key['id']}", ctx).json()["privatekey"].rstrip("\n")
        )
        for key in present_keys.json()
    )


def lowercase_secret(secret: str) -> str:
    """Splits the private key of a dnssec into the secret and metadata part and lowercases the
    metadata for comparison purposes"""
    last_colon_index = secret.rfind(":")
    before_last_colon = secret[:last_colon_index]
    after_last_colon = secret[last_colon_index:]
    return before_last_colon.lower() + after_last_colon


def does_cryptokey_exist(
    uri: str, exit_message: str, exit_code: int, ctx: click.Context
) -> requests.Response:
    """Checks if the DNS cryptokey already exists in the backend.

    Sends a GET request to the provided `uri` to check for the existence of a DNS cryptokey.
    If the response status code is 404, it prints the provided `exit_message` and exits
    with the specified `exit_code`. Otherwise, it returns the response object.

    Args:
        uri (str): The URI to check for the DNS cryptokey.
        exit_message (str): The message to display if the cryptokey does not exist.
        exit_code (int): The exit code to use if the cryptokey does not exist.
        ctx (click.Context): Click context object for command-line operations.

    Returns:
        requests.Response: The HTTP response object if the cryptokey exists.

    Raises:
        SystemExit: If the cryptokey does not exist (HTTP 404 response).
    """
    r = utils.http_get(uri, ctx)
    if r.status_code == 404:
        utils.print_output({"message": exit_message})
        raise SystemExit(exit_code)
    return r
