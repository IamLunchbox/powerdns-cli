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

import click

from ..utils import main as utils


@click.group()
def tsigkey():
    """Set up tsigkeys"""


@tsigkey.command("add")
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
@click.pass_context
def tsigkey_add(ctx, name, algorithm, secret):
    """
    Adds a TSIGKey to the server to sign dns transfer messages
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/tsigkeys"
    payload = {"name": name, "algorithm": algorithm}
    if secret:
        payload["key"] = secret
    r = utils.http_get(f"{uri}/{name}", ctx)
    if r.status_code == 200 and secret:
        if r.json()["key"] == secret:
            utils.print_output(
                {"message": f"A TSIGKEY with {name} and your secret is already present"}
            )
        raise SystemExit(0)
    if r.status_code == 200:
        utils.print_output({"message": f"A TSIGKEY with name {name} is already present"})
        raise SystemExit(0)
    r = utils.http_post(uri, ctx, payload)
    if utils.create_output(
        r,
        (201,),
    ):
        raise SystemExit(0)
    raise SystemExit(1)


@tsigkey.command("delete")
@click.argument("name", type=click.STRING)
@click.pass_context
def tsigkey_delete(ctx, name):
    """
    Deletes the TSIG-Key with the given name
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/tsigkeys/{name}"
    r = utils.http_get(uri, ctx)
    if not r.status_code == 200:
        utils.print_output({"message": f"TSIGKEY for {name} already absent"})
        raise SystemExit(0)
    r = utils.http_delete(uri, ctx)
    if utils.create_output(r, (204,), optional_json={"message": f"Deleted TSIGKEY {name}"}):
        raise SystemExit(0)
    raise SystemExit(1)


@tsigkey.command("export")
@click.pass_context
@click.argument(
    "key-id",
    type=click.STRING,
)
def tsigkey_export(ctx, key_id):
    """
    Exports a tsigkey with the given id
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/tsigkeys/{key_id}"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@tsigkey.command("import")
@click.argument("file", type=click.File())
@click.option(
    "--replace",
    type=click.BOOL,
    is_flag=True,
    help="Replace all network settings with new ones",
)
@click.option(
    "--ignore-errors", type=click.BOOL, is_flag=True, help="Continue import even when requests fail"
)
@click.pass_context
def tsigkey_import(ctx, file, replace, ignore_errors):
    """Import TSIG keys from a file, with optional replacement of existing keys."""
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/tsigkeys"
    settings = utils.extract_file(file)
    upstream_settings = get_tsigkey_settings(uri, ctx)
    utils.validate_simple_import(ctx, settings, upstream_settings, replace)
    if replace and upstream_settings:
        replace_tsigkey_import(uri, ctx, settings, upstream_settings, ignore_errors)
    else:
        add_tsigkey_import(uri, ctx, settings, ignore_errors)
    utils.print_output(
        {"message": "Successfully imported tsigkeys"},
    )
    raise SystemExit(0)


@tsigkey.command("list")
@click.pass_context
def tsigkey_list(ctx):
    """
    Shows the TSIGKeys for this server
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/tsigkeys"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@tsigkey.command("spec")
def tsigkey_spec():
    """Open the tsigkey specification on https://redocly.github.io"""

    utils.open_spec("tsigkey")


@tsigkey.command("update")
@click.argument("name", type=click.STRING)
@click.option(
    "-a",
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
@click.pass_context
def tsigkey_update(ctx, name, algorithm, secret, new_name):
    """
    Updates or renames an existing TSIGKey
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/tsigkeys/{name}"
    tsikey_settings = {
        k: v for k, v in {"algorithm": algorithm, "key": secret, "name": new_name}.items() if v
    }
    r = utils.http_get(uri, ctx)
    if r.status_code != 200:
        utils.print_output({"error": f"A TSIGKEY with name {name} does not exist"})
        raise SystemExit(1)
    if all(tsikey_settings[setting] == r.json()[setting] for setting in tsikey_settings):
        utils.print_output({"message": f"The settings TSIGKEY {name} are already present"})
        raise SystemExit(0)
    if new_name:
        r = utils.http_get(f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/tsigkeys", ctx)
        if new_name in (key["name"] for key in r.json()):
            utils.print_output({"error": f"TSIGKEY {name} already exists. Refusing to rewrite."})
            raise SystemExit(1)
    r = utils.http_put(uri, ctx, tsikey_settings)
    if utils.create_output(
        r,
        (200,),
    ):
        raise SystemExit(0)
    raise SystemExit(1)


def get_tsigkey_settings(uri: str, ctx: click.Context) -> list[dict]:
    """Retrieve all TSIG keys and their key contents as a list of dictionaries.

    This function fetches TSIG keys from the specified URI and returns their settings.

    Args:
        uri: The base connection string to the API endpoint.
        ctx: Click context object for CLI operations, used for HTTP requests.

    Returns:
        A list of dictionaries, where each dictionary contains the settings of a TSIG key.

    Raises:
        SystemExit: If there is an error decoding the JSON response from the API.
    """
    upstream_tsigkey_list = utils.read_settings_from_upstream(uri, ctx)
    try:
        upstream_settings = [
            utils.http_get(f"{uri}/{item['id']}", ctx).json() for item in upstream_tsigkey_list
        ]
    except json.JSONDecodeError as e:
        utils.print_output({"error": f"Failed to download TSIG keys for deduplication: {e}"})
        raise SystemExit(1) from e
    return upstream_settings


def replace_tsigkey_import(
    uri: str, ctx: click.Context, settings: list, upstream_settings: list, ignore_errors: bool
) -> None:
    """
    Replace TSIG keys by performing a complete synchronization operation.

    This function ensures the upstream configuration exactly matches the provided settings by:
    1. Identifying which keys already exist and match (no action needed)
    2. Adding new keys that don't exist upstream
    3. Removing upstream keys that aren't in the new settings

    Args:
        uri: API endpoint URI for TSIG keys
        ctx: Click context object containing authentication and configuration
        settings: List of desired TSIG key configurations
        upstream_settings: List of current upstream TSIG key configurations
        ignore_errors: If True, continue processing despite individual failures
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
            r = utils.http_post(uri, ctx, payload=new_tsigkey)
            if r.status_code != 201:
                utils.handle_import_early_exit(
                    ctx,
                    f"Failed adding tsigkey {new_tsigkey['name']}",
                    ignore_errors,
                )

    for upstream_tsigkey in upstreams_to_delete:
        r = utils.http_delete(f"{uri}/{upstream_tsigkey['name']}", ctx)
        if r.status_code != 204:
            utils.handle_import_early_exit(
                ctx,
                f"Failed deleting tsigkey {upstream_tsigkey['name']}",
                ignore_errors,
            )


def add_tsigkey_import(uri: str, ctx: click.Context, settings: list, ignore_errors: bool) -> None:
    """
    Import TSIG keys by adding them to the upstream configuration.

    Accepts both successful creation (201) and conflicts (409) as valid outcomes,
    allowing for idempotent operations where existing keys are not modified.

    Args:
        uri: API endpoint URI for TSIG keys
        ctx: Click context object containing authentication and configuration
        settings: List of TSIG key configurations to import
        ignore_errors: If True, continue processing despite errors
    """

    for new_tsigkey in settings:
        r = utils.http_post(f"{uri}", ctx, payload=new_tsigkey)
        if r.status_code not in (201, 409):
            utils.handle_import_early_exit(
                ctx,
                f"ailed adding tsigkey {new_tsigkey['name']}",
                ignore_errors,
            )
