"""
A Click-based CLI module for managing TSIG keys in PowerDNS.
This module provides a comprehensive set of commands for managing TSIG (Transaction Signature)
keys, which are used to authenticate DNS transactions such as zone transfers.
Commands:
    add: Adds a new TSIG key with a specified name, algorithm, and optional secret.
    delete: Deletes an existing TSIG key by name.
    export: Exports the details of a TSIG key by its ID.
    import: Imports TSIG keys from a file, with options to replace existing keys or ignore errors.
    list: Lists all TSIG keys configured on the server.
    update: Updates or renames an existing TSIG key.
    spec: Opens the TSIG key API specification in the browser.
"""

import json
from typing import NoReturn, TextIO

import click

from ..utils import main as utils
from ..utils.validation import DefaultCommand


@click.group()
def tsigkey():
    """Set up server wide TSIGKeys, to sign transfer messages."""


@tsigkey.command(
    "add",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.pass_context
@click.argument("name", type=click.STRING)
@click.argument(
    "algorithm",
    type=click.Choice(
        [
            "hmac-md5",
            "hmac-sha1",
            "hmac-sha224",
            "hmac-sha256",
            "hmac-sha384",
            "hmac-sha512",
        ]
    ),
)
@click.option("-s", "--secret", type=click.STRING)
def tsigkey_add(ctx: click.Context, name: str, algorithm: str, secret: str, **kwargs) -> NoReturn:
    """
    Adds a TSIGKey to the server to sign DNS transfer messages.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/tsigkeys"
    payload = {"name": name, "algorithm": algorithm}
    if secret:
        payload["key"] = secret
    r = utils.http_get(f"{uri}/{name}", ctx)
    if r.status_code == 200:
        if secret and r.json()["key"] == secret:
            ctx.obj.logger.info(
                f"TSIGKey with name '{name}' and the provided secret already exists."
            )
            utils.exit_action(
                ctx, True, f"A TSIGKey with name '{name}' and your secret is already present."
            )
        ctx.obj.logger.info(f"TSIGKey with name '{name}' already exists.")
        utils.exit_action(ctx, True, f"A TSIGKey with name '{name}' is already present.")
    r = utils.http_post(uri, ctx, payload)
    if r.status_code == 201:
        ctx.obj.logger.info(f"Successfully added TSIGKey with name '{name}'.…")
        utils.exit_action(ctx, True, f"Successfully added TSIGKey with name '{name}'.", r)
    else:
        ctx.obj.logger.error(f"Failed to add TSIGKey with name '{name}'.")
        utils.exit_action(ctx, False, f"Failed to add TSIGKey with name '{name}'.", r)


@tsigkey.command(
    "delete",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.pass_context
@click.argument("name", type=click.STRING)
def tsigkey_delete(ctx: click.Context, name: str, **kwargs) -> NoReturn:
    """
    Deletes the TSIG-Key with the given name.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/tsigkeys/{name}"
    r = utils.http_get(uri, ctx)
    if r.status_code != 200:
        ctx.obj.logger.info(f"TSIGKey for '{name}' is already absent.")
        utils.exit_action(ctx, True, f"TSIGKey for '{name}' is already absent.")
    r = utils.http_delete(uri, ctx)
    if r.status_code == 204:
        ctx.obj.logger.info(f"Successfully deleted TSIGKey '{name}'.")
        utils.exit_action(ctx, True, f"Successfully deleted TSIGKey '{name}'.", r)
    else:
        ctx.obj.logger.error(f"Failed to delete TSIGKey '{name}'.")
        utils.exit_action(ctx, False, f"Failed to delete TSIGKey '{name}'.", r)


@tsigkey.command(
    "export",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.pass_context
@click.argument(
    "key-id",
    type=click.STRING,
)
def tsigkey_export(ctx: click.Context, key_id: str, **kwargs):
    """
    Exports a single tsigkey with the given id and its secret key.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/tsigkeys/{key_id}"
    utils.show_setting(ctx, uri, "tsigkey", "export")


@tsigkey.command(
    "import",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.pass_context
@click.argument("file", type=click.File())
@click.option(
    "--replace",
    is_flag=True,
    help="Replace all TSIG keys with new ones.",
)
@click.option(
    "--ignore-errors",
    is_flag=True,
    help="Continue import even when requests fail.",
)
def tsigkey_import(
    ctx: click.Context, file: TextIO, replace: bool, ignore_errors: bool, **kwargs
) -> NoReturn:
    """
    Import TSIG keys from a file.
    When replacement is requested, non-matching existing keys will be deleted as well.
    File format:
    [{ "algorithm": str, "id": str, "key": str, "name": str, "type": "TSIGKey" }]

    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/tsigkeys"
    settings = utils.extract_file(ctx, file)
    upstream_settings = get_tsigkey_settings(uri, ctx)
    utils.validate_simple_import(ctx, settings, upstream_settings, replace)
    if replace and upstream_settings:
        ctx.obj.logger.info("Replacing existing TSIG keys.")
        replace_tsigkey_import(uri, ctx, settings, upstream_settings, ignore_errors)
    else:
        ctx.obj.logger.info("Adding new TSIG keys.")
        add_tsigkey_import(uri, ctx, settings, ignore_errors)


@tsigkey.command(
    "list",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
)
@click.pass_context
def tsigkey_list(ctx: click.Context, **kwargs) -> NoReturn:
    """
    Shows the TSIGKeys for this server.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/tsigkeys"
    utils.show_setting(ctx, uri, "tsigkey", "list")


@tsigkey.command("spec")
def tsigkey_spec():
    """Open the tsigkey specification on https://redocly.github.io."""
    utils.open_spec("tsigkey")


@tsigkey.command(
    "update",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.pass_context
@click.argument("name", type=click.STRING)
@click.option(
    "--algorithm",
    type=click.Choice(
        [
            "hmac-md5",
            "hmac-sha1",
            "hmac-sha224",
            "hmac-sha256",
            "hmac-sha384",
            "hmac-sha512",
        ]
    ),
)
@click.option("-s", "--secret", type=click.STRING)
@click.option("-n", "--new-name", type=click.STRING)
def tsigkey_update(
    ctx: click.Context, name: str, algorithm: str, secret: str, new_name: str, **kwargs
) -> NoReturn:
    """
    Updates or renames an existing TSIGKey.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/tsigkeys/{name}"
    tsigkey_settings = {
        k: v
        for k, v in {"algorithm": algorithm, "key": secret, "name": new_name}.items()
        if v is not None
    }
    r = utils.http_get(uri, ctx)
    if r.status_code != 200:
        ctx.obj.logger.error(f"TSIGKey with name '{name}' does not exist.")
        utils.exit_action(ctx, False, f"TSIGKey with name '{name}' does not exist.")
    if all(tsigkey_settings.get(setting) == r.json().get(setting) for setting in tsigkey_settings):
        ctx.obj.logger.info(f"Settings for TSIGKey '{name}' are already up to date.")
        utils.exit_action(ctx, True, f"Settings for TSIGKey '{name}' are already up to date.")
    if new_name:
        r = utils.http_get(f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/tsigkeys", ctx)
        if new_name in (key["name"] for key in r.json()):
            ctx.obj.logger.error(f"TSIGKey '{new_name}' already exists. Refusing to overwrite.")
            utils.exit_action(
                ctx, False, f"TSIGKey '{new_name}' already exists. Refusing to overwrite."
            )
    r = utils.http_put(uri, ctx, tsigkey_settings)
    if r.status_code == 200:
        ctx.obj.logger.info(f"Successfully updated TSIGKey '{name}'.")
        utils.exit_action(ctx, True, f"Successfully updated TSIGKey '{name}'.", r)
    else:
        ctx.obj.logger.error(f"Failed to update TSIGKey '{name}'. Status code: {r.status_code}.")
        utils.exit_action(ctx, False, f"Failed to update TSIGKey '{name}'.", r)


def get_tsigkey_settings(uri: str, ctx: click.Context) -> list[dict]:
    """Retrieve all TSIG keys and their key contents as a list of dictionaries.

    Args:
        uri: The base connection string to the API endpoint.
        ctx: Click context object for CLI operations, used for HTTP requests.

    Returns:
        A list of dictionaries, where each dictionary contains the settings of a TSIG key.
    """
    upstream_tsigkey_list = utils.read_settings_from_upstream(uri, ctx)
    upstream_settings = []
    for item in upstream_tsigkey_list:
        r = utils.http_get(f"{uri}/{item['id']}", ctx)
        try:
            upstream_settings.append(r.json())
        except json.JSONDecodeError as e:
            ctx.obj.logger.error(f"Failed to decode JSON for TSIG key {item['id']}: {e}.")
            utils.exit_action(ctx, False, f"Failed to decode JSON for TSIG key {item['id']}: {e}.")
    return upstream_settings


def replace_tsigkey_import(
    uri: str,
    ctx: click.Context,
    settings: list[dict],
    upstream_settings: list[dict],
    ignore_errors: bool,
) -> None:
    """Replace TSIG keys by performing a complete synchronization operation.
    This function ensures the upstream configuration exactly matches the provided settings by:
    1. Identifying which keys already exist and match (no action needed).
    2. Adding new keys that don't exist upstream.
    3. Removing upstream keys that aren't in the new settings.

    Args:
        uri: API endpoint URI for TSIG keys.
        ctx: Click context object containing authentication and configuration.
        settings: List of desired TSIG key configurations.
        upstream_settings: List of current upstream TSIG key configurations.
        ignore_errors: If True, continue processing despite individual failures.
    """
    existing_upstreams = []
    upstreams_to_delete = []
    for upstream_tsigkey in upstream_settings:
        if upstream_tsigkey in settings:
            existing_upstreams.append(upstream_tsigkey)
        else:
            upstreams_to_delete.append(upstream_tsigkey)
    for new_tsigkey in settings:
        if new_tsigkey not in existing_upstreams:
            ctx.obj.logger.info(f"Adding TSIG key: {new_tsigkey['name']}.")
            r = utils.http_post(uri, ctx, payload=new_tsigkey)
            if r.status_code != 201:
                ctx.obj.logger.error(f"Failed to add TSIG key: {new_tsigkey['name']}.")
                if not ignore_errors:
                    utils.exit_action(ctx, False, f"Failed to add TSIG key: {new_tsigkey['name']}.")
    for upstream_tsigkey in upstreams_to_delete:
        ctx.obj.logger.info(f"Deleting TSIG key: {upstream_tsigkey['name']}.")
        r = utils.http_delete(f"{uri}/{upstream_tsigkey['name']}", ctx)
        if r.status_code != 204:
            ctx.obj.logger.error(f"Failed to delete TSIG key: {upstream_tsigkey['name']}.")
            if not ignore_errors:
                utils.exit_action(
                    ctx, False, f"Failed to delete TSIG key: {upstream_tsigkey['name']}."
                )
    ctx.obj.logger.info("Successfully replaced tsigkey settings.")
    utils.exit_action(ctx, True, "Successfully replaced tsigkey settings.")


def add_tsigkey_import(
    uri: str,
    ctx: click.Context,
    settings: list[dict],
    ignore_errors: bool,
) -> None:
    """Import TSIG keys by adding them to the upstream configuration.
    Accepts both successful creation (201) and conflicts (409) as valid outcomes,
    allowing for idempotent operations where existing keys are not modified.

    Args:
        uri: API endpoint URI for TSIG keys.
        ctx: Click context object containing authentication and configuration.
        settings: List of TSIG key configurations to import.
        ignore_errors: If True, continue processing despite errors.
    """
    for new_tsigkey in settings:
        ctx.obj.logger.debug(f"Attempting to add TSIG key: {new_tsigkey['name']}.")
        r = utils.http_post(uri, ctx, payload=new_tsigkey)
        if r.status_code not in (201, 409):
            ctx.obj.logger.error(f"Failed to add TSIG key: {new_tsigkey['name']}.")
            if not ignore_errors:
                utils.exit_action(ctx, False, f"Failed to add TSIG key: {new_tsigkey['name']}.")
    ctx.obj.logger.info("Successfully imported tsigkey settings.")
    utils.exit_action(ctx, True, "Successfully replaced tsigkey settings.")
