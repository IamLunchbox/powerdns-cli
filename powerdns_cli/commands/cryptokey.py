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

from typing import NoReturn, TextIO

import click
import requests

from ..utils import main as utils
from ..utils.validation import DefaultCommand, powerdns_zone


@click.group()
def cryptokey():
    """Manage DNSSEC-Keys.

    This action allows configuring DNSSEC-Keys for a single zone. Keys can be published and active.
    Simply creating or importing an active key does activate DNSSEC automatically.
    """


@cryptokey.command(
    "add",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.pass_context
@click.argument("key-type", type=click.Choice(["ksk", "zsk"]))
@click.argument(
    "algorithm",
    type=click.Choice(
        ["rsasha1", "rsasha256", "rsasha512", "ecdsap256sha256", "ed25519", "ed448"],
        case_sensitive=False,
    ),
)
@powerdns_zone
@click.option(
    "--active",
    is_flag=True,
    default=False,
    help="Sets the key to active immediately",
)
@click.option("-p", "--publish", is_flag=True, default=False, help="Sets the key to published")
@click.option("-b", "--bits", type=click.INT, help="Set the key size in bits, required for ZSK")
def cryptokey_add(
    ctx: click.Context,
    key_type: str,
    algorithm: str,
    dns_zone: str,
    active: bool,
    publish: bool,
    bits: int,
    **kwargs: dict,
) -> NoReturn:
    """
    Adds a cryptokey to the zone.

    A new cryptokey is disabled and not published by default. Either add the flags here or use
    publish / active with the appropriate id to change the setting later on.
    If an RSA key is requested, the size of the rsa-key must be specified as well.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys"
    payload = {"active": active, "published": publish, "keytype": key_type, "algorithm": algorithm}
    if bits:
        payload["bits"] = bits

    if payload.get("algorithm", "").startswith("rsa") and not payload.get("bits"):
        ctx.obj.logger.error(
            "Setting a key with a rsa algorithm requires a bitsize to be passed as well."
        )
        utils.exit_action(
            ctx,
            success=False,
            message="Setting a key with a rsa algorithm requires a bitsize to be passed as well.",
        )
    ctx.obj.logger.info(
        f"Attempting to add a new cryptokey of type '{key_type}' for zone '{dns_zone}'."
    )
    r = utils.http_post(uri, ctx, payload, log_body=False)
    if r.status_code == 201:
        ctx.obj.logger.info(
            f"Successfully added a new cryptokey with id '{r.json()['id']}' for zone '{dns_zone}'."
        )
        utils.exit_action(
            ctx,
            success=True,
            message=f"Added a new cryptokey with id {r.json()['id']}.",
        )
    elif r.status_code == 404:
        ctx.obj.logger.error(f"Failed to create the DNSSEC key: zone '{dns_zone}' does not exist.")
        utils.exit_action(
            ctx,
            success=False,
            message=f"Failed creating the DNSSEC key, zone '{dns_zone}' does not exist.",
            response=r,
        )
    else:
        ctx.obj.logger.error(f"Failed to create the DNSSEC key for zone '{dns_zone}'.")
        utils.exit_action(
            ctx,
            success=False,
            message="Failed creating the DNSSEC key.",
            response=r,
        )


@cryptokey.command(
    "delete",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.pass_context
@powerdns_zone
@click.argument("cryptokey-id", type=click.INT)
def cryptokey_delete(
    ctx: click.Context, dns_zone: str, cryptokey_id: int, **kwargs: dict
) -> NoReturn:
    """
    Deletes a cryptokey.
    """
    uri = (
        f"{ctx.obj.config['apihost']}"
        f"/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys/{cryptokey_id}"
    )
    ctx.obj.logger.info(
        f"Attempting to delete cryptokey with id '{cryptokey_id}' for zone '{dns_zone}'."
    )

    exit_if_cryptokey_does_not_exist(
        ctx, uri, f"Cryptokey with id '{cryptokey_id}' already absent.", success=True
    )

    r = utils.http_delete(uri, ctx)
    if r.status_code == 204:
        ctx.obj.logger.info(
            f"Successfully deleted cryptokey with id '{cryptokey_id}' for zone '{dns_zone}'."
        )
        utils.exit_action(
            ctx, success=True, message=f"Deleted id '{cryptokey_id}' for '{dns_zone}'.", response=r
        )
    else:
        ctx.obj.logger.error(
            f"Failed to delete cryptokey with id '{cryptokey_id}' for zone '{dns_zone}'."
        )
        ctx.obj.handler.set_data(r)
        utils.exit_action(
            ctx,
            success=False,
            message=f"Failed to delete id '{cryptokey_id}' for '{dns_zone}'.",
            response=r,
        )


@cryptokey.command(
    "disable",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.pass_context
@powerdns_zone
@click.argument("cryptokey-id", type=click.INT)
def cryptokey_disable(
    ctx: click.Context, dns_zone: str, cryptokey_id: int, **kwargs: dict
) -> NoReturn:
    """
    Disables a cryptokey.
    """
    uri = (
        f"{ctx.obj.config['apihost']}"
        f"/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys/{cryptokey_id}"
    )
    payload = {"id": cryptokey_id, "active": False}

    ctx.obj.logger.info(
        f"Attempting to disable cryptokey with id '{cryptokey_id}' for zone '{dns_zone}'."
    )

    r = exit_if_cryptokey_does_not_exist(
        ctx, uri, f"Cryptokey with id '{cryptokey_id}' does not exist.", success=False
    )

    if not r.json()["active"]:
        ctx.obj.logger.info(f"Cryptokey with id '{cryptokey_id}' is already inactive.")
        utils.exit_action(
            ctx,
            success=True,
            message=f"Cryptokey with id '{cryptokey_id}' is already inactive.",
        )

    r = utils.http_put(uri, ctx, payload)
    if r.status_code == 204:
        ctx.obj.logger.info(
            f"Successfully disabled cryptokey with id '{cryptokey_id}' for zone '{dns_zone}'."
        )
        utils.exit_action(
            ctx,
            success=True,
            message=f"Disabled id '{cryptokey_id}' for '{dns_zone}'.",
            response=r,
        )
    else:
        ctx.obj.logger.error(
            f"Failed to disable cryptokey with id '{cryptokey_id}' for zone '{dns_zone}'."
        )
        ctx.obj.handler.set_data(r)
        utils.exit_action(
            ctx,
            success=False,
            message=f"Failed disabling '{cryptokey_id}' for '{dns_zone}'.",
            response=r,
        )


@cryptokey.command(
    "enable",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.pass_context
@powerdns_zone
@click.argument("cryptokey-id", type=click.INT)
def cryptokey_enable(
    ctx: click.Context, dns_zone: str, cryptokey_id: int, **kwargs: dict
) -> NoReturn:
    """
    Enables a cryptokey.
    """
    uri = (
        f"{ctx.obj.config['apihost']}"
        f"/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys/{cryptokey_id}"
    )
    payload = {"id": cryptokey_id, "active": True}

    ctx.obj.logger.info(
        f"Attempting to enable cryptokey with id '{cryptokey_id}' for zone '{dns_zone}'."
    )

    r = exit_if_cryptokey_does_not_exist(
        ctx, uri, f"Cryptokey with id '{cryptokey_id}' does not exist.", success=False
    )

    if r.json()["active"]:
        ctx.obj.logger.info(f"Cryptokey with id '{cryptokey_id}' is already active.")
        utils.exit_action(
            ctx,
            success=True,
            message=f"Cryptokey with id '{cryptokey_id}' is already active.",
        )

    r = utils.http_put(uri, ctx, payload)
    if r.status_code == 204:
        ctx.obj.logger.info(
            f"Successfully enabled cryptokey with id '{cryptokey_id}' for zone '{dns_zone}'."
        )
        utils.exit_action(
            ctx,
            success=True,
            message=f"Enabled id '{cryptokey_id}' for '{dns_zone}'.",
            response=r,
        )
    else:
        ctx.obj.logger.error(
            f"Failed to enable cryptokey with id '{cryptokey_id}' for zone '{dns_zone}'."
        )
        ctx.obj.handler.set_data(r)
        utils.exit_action(
            ctx,
            success=False,
            message=f"Failed enabling '{cryptokey_id}' for '{dns_zone}'",
            response=r,
        )


@cryptokey.command(
    "export",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.pass_context
@powerdns_zone
@click.argument("cryptokey-id", type=click.STRING)
def cryptokey_export(
    ctx: click.Context, dns_zone: str, cryptokey_id: str, **kwargs: dict
) -> NoReturn:
    """
    Exports a cryptokey, including the private key.
    """
    uri = (
        f"{ctx.obj.config['apihost']}"
        f"/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys/{cryptokey_id}"
    )

    ctx.obj.logger.info(
        f"Attempting to export cryptokey with id '{cryptokey_id}' for zone '{dns_zone}'."
    )

    r = exit_if_cryptokey_does_not_exist(
        ctx, uri, f"Cryptokey with id '{cryptokey_id}' does not exist.", success=False
    )

    if r.status_code == 200:
        ctx.obj.logger.info(f"Exporting cryptokey with id '{cryptokey_id}' for zone '{dns_zone}'.")
        utils.exit_action(
            ctx,
            success=True,
            message=f"Exported cryptokey with id '{cryptokey_id}' for '{dns_zone}'.",
            response=r,
            print_data=True,
        )
    else:
        ctx.obj.logger.error(
            f"Failed to export cryptokey with id '{cryptokey_id}' for zone '{dns_zone}'."
        )
        ctx.obj.handler.set_data(r)
        utils.exit_action(
            ctx,
            success=False,
            message=f"Failed to export cryptokey with id '{cryptokey_id}' for '{dns_zone}'.",
            response=r,
        )


@cryptokey.command(
    "import",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.pass_context
@click.argument("key-type", type=click.Choice(["ksk", "zsk"]))
@powerdns_zone
@click.argument("private-key", type=click.File())
def cryptokey_import(
    ctx: click.Context,
    key_type: str,
    dns_zone: str,
    private_key: TextIO,
    **kwargs: dict,
) -> NoReturn:
    """
    Imports a cryptokey secret to the zone.

    The imported cryptokey is disabled and not published by default.
    Can be read from stdin when '-' is used instead of a file path.
    Only privatekey is required, powerdns defaults to published: True and active: False.
    File format:
    {"privatekey": "Yourprivatekey", "active": bool, "published": bool}
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys"
    secret = utils.extract_file(ctx, private_key)
    if not secret.get("privatekey"):
        ctx.obj.logger.error("Failed importing the file, dict key 'privatekey' is missing.")
        utils.exit_action(
            ctx,
            success=False,
            message="Failed importing the file, dict key 'privatekey' is missing.",
        )
    key = secret["privatekey"].replace("\\n", "\n")
    payload = {
        "active": secret.get("active"),
        "published": secret.get("published"),
        "privatekey": key,
        "keytype": key_type,
    }

    ctx.obj.logger.info(
        f"Attempting to import cryptokey of type '{key_type}' for zone '{dns_zone}'."
    )

    if is_dnssec_key_present(uri, key, ctx):
        ctx.obj.logger.info("The provided DNSSEC key is already present at the backend.")
        utils.exit_action(
            ctx,
            success=True,
            message="The provided DNSSEC key is already present at the backend.",
        )

    r = utils.http_post(uri, ctx, payload)
    if r.status_code == 201:
        ctx.obj.logger.info(f"Successfully imported cryptokey for zone '{dns_zone}'.")
        utils.exit_action(
            ctx,
            success=True,
            message="Successfully imported cryptokey.",
            response=r,
        )
    else:
        ctx.obj.logger.error(f"Failed to import cryptokey for zone '{dns_zone}'.")
        utils.exit_action(
            ctx,
            success=False,
            message="Failed importing cryptokey.",
            response=r,
        )


@cryptokey.command(
    "list",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.pass_context
@powerdns_zone
def cryptokey_list(ctx: click.Context, dns_zone: str, **kwargs: dict) -> NoReturn:
    """
    Lists all cryptokeys without displaying secrets.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys"

    ctx.obj.logger.info(f"Attempting to list cryptokeys for zone '{dns_zone}'.")

    r = utils.http_get(uri, ctx)
    if r.status_code == 200:
        ctx.obj.logger.info(f"Successfully retrieved cryptokeys for zone '{dns_zone}'.")
        utils.exit_action(
            ctx,
            success=True,
            message=f"List of cryptokeys for zone '{dns_zone}'.",
            response=r,
            print_data=True,
        )
    else:
        ctx.obj.logger.error(f"Failed to list cryptokeys for zone '{dns_zone}'.")
        utils.exit_action(
            ctx,
            success=False,
            message=f"Failed to list cryptokeys for zone '{dns_zone}'.",
            response=r,
        )


@cryptokey.command(
    "publish",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.pass_context
@powerdns_zone
@click.argument("cryptokey-id", type=click.INT)
def cryptokey_publish(
    ctx: click.Context, dns_zone: str, cryptokey_id: int, **kwargs: dict
) -> NoReturn:
    """
    Publishes a cryptokey.
    """
    uri = (
        f"{ctx.obj.config['apihost']}"
        f"/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys/{cryptokey_id}"
    )
    payload = {"id": cryptokey_id, "published": True}

    ctx.obj.logger.info(
        f"Attempting to publish cryptokey with id '{cryptokey_id}' for zone '{dns_zone}'."
    )

    r = exit_if_cryptokey_does_not_exist(
        ctx, uri, f"Cryptokey with id '{cryptokey_id}' does not exist.", success=False
    )

    if r.json()["published"]:
        ctx.obj.logger.info(f"Cryptokey with id '{cryptokey_id}' is already published.")
        utils.exit_action(
            ctx,
            success=True,
            message=f"Cryptokey with id '{cryptokey_id}' already published.",
        )

    payload["active"] = r.json()["active"]
    r = utils.http_put(uri, ctx, payload)
    if r.status_code == 204:
        ctx.obj.logger.info(
            f"Successfully published cryptokey with id '{cryptokey_id}' for zone '{dns_zone}'."
        )
        utils.exit_action(
            ctx,
            success=True,
            message=f"Published id '{cryptokey_id}' for '{dns_zone}'.",
            response=r,
        )
    else:
        ctx.obj.logger.error(
            f"Failed to publish cryptokey with id '{cryptokey_id}' for zone '{dns_zone}'."
        )
        utils.exit_action(
            ctx,
            success=False,
            message=f"Failed publishing '{cryptokey_id}' for '{dns_zone}'.",
            response=r,
        )


@cryptokey.command("spec")
def cryptokey_spec():
    """Open the cryptokey specification on https://redocly.github.io"""

    utils.open_spec("cryptokey")


@cryptokey.command(
    "unpublish",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.pass_context
@powerdns_zone
@click.argument("cryptokey-id", type=click.INT)
def cryptokey_unpublish(
    ctx: click.Context, dns_zone: str, cryptokey_id: int, **kwargs: dict
) -> NoReturn:
    """
    Unpublishes a cryptokey.
    """
    uri = (
        f"{ctx.obj.config['apihost']}"
        f"/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys/{cryptokey_id}"
    )
    payload = {"id": cryptokey_id, "published": False}

    ctx.obj.logger.info(
        f"Attempting to unpublish cryptokey with id '{cryptokey_id}' for zone '{dns_zone}'."
    )

    r = exit_if_cryptokey_does_not_exist(
        ctx, uri, f"Cryptokey with id '{cryptokey_id}' does not exist.", success=False
    )

    if not r.json()["published"]:
        ctx.obj.logger.info(f"Cryptokey with id '{cryptokey_id}' is already unpublished.")
        utils.exit_action(
            ctx,
            success=True,
            message=f"Cryptokey '{cryptokey_id}' is already unpublished.",
        )

    payload["active"] = r.json()["active"]
    r = utils.http_put(uri, ctx, payload)
    if r.status_code == 204:
        ctx.obj.logger.info(
            f"Successfully unpublished cryptokey with id '{cryptokey_id}' for zone '{dns_zone}'."
        )
        utils.exit_action(
            ctx,
            success=True,
            message=f"Unpublished '{cryptokey_id}' for '{dns_zone}'",
            response=r,
        )
    else:
        ctx.obj.logger.error(
            f"Failed to unpublish cryptokey with id '{cryptokey_id}' for zone '{dns_zone}'."
        )
        utils.exit_action(
            ctx,
            success=False,
            message=f"Failed unpublishing '{cryptokey_id}' for '{dns_zone}'.",
            response=r,
        )


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


def exit_if_cryptokey_does_not_exist(
    ctx: click.Context, uri: str, exit_message: str, success: bool = False
) -> requests.Response:
    """Checks if the DNS cryptokey already exists in the backend.

    Sends a GET request to the provided `uri` to check for the existence of a DNS cryptokey.
    If the response status code is 404, it prints the provided `exit_message` and exits.
    Otherwise, it returns the response object.

    Args:
        uri (str): The URI to check for the DNS cryptokey.
        exit_message (str): The message to display if the cryptokey does not exist.
        ctx (click.Context): Click context object for command-line operations.
        success (bool): Optionally overwrite the stats from failed to success.

    Returns:
        requests.Response: The HTTP response object if the cryptokey exists.

    Raises:
        SystemExit: If the cryptokey does not exist (HTTP 404 response).
    """
    r = utils.http_get(uri, ctx)
    if r.status_code == 404:
        if success:
            ctx.obj.logger.info("Requested cryptokey does not exist.")
        else:
            ctx.obj.logger.error("Requested cryptokey does not exist.")
        utils.exit_action(ctx, success=success, message=exit_message)
    ctx.obj.logger.info("Requested cryptokey is present.")
    return r
