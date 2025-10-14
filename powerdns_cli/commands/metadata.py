"""
A Click-based CLI module for managing DNS zone metadata in PowerDNS.
This module provides commands for managing metadata associated with DNS zones.
Commands:
    add: Adds a new metadata entry to a DNS zone.
    delete: Deletes a metadata entry from a DNS zone.
    extend: Appends a new item to an existing metadata list for a DNS zone.
    import: Imports metadata for a DNS zone from a file, with options to replace or ignore errors.
    export: Exports metadata for a DNS zone, optionally limited to a single key.
    update: Replaces an existing metadata entry for a DNS zone.
    spec: Opens the metadata API specification in the browser.
"""

from typing import NoReturn

import click

from ..utils import main as utils
from ..utils.validation import DefaultCommand, powerdns_zone


@click.group()
def metadata():
    """Configure zone metadata.
    Metadata has a predefined list of metadata entries, which are validated by the server.
    If an entry does not match the list, the update will be rejected.
    It is possible to set custom metadata, if the name starts with 'X-'.
    SOA-EDIT-API may not be edited through the CLI.
    The list of valid metadata items can be found here:
    https://doc.powerdns.com/authoritative/domainmetadata.html.
    """


@metadata.command(
    "add",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@powerdns_zone
@click.argument("metadata-key", type=click.STRING)
@click.argument("metadata-value", type=click.STRING)
@click.pass_context
def metadata_add(ctx, dns_zone, metadata_key, metadata_value, **kwargs):
    """
    Adds metadata to a zone.
    Valid dictionary metadata-keys are not arbitrary and must conform to the expected content
    from the PowerDNS configuration.
    Custom metadata must be preceded by leading X- as a key.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/metadata"
    payload = {"kind": metadata_key, "metadata": [metadata_value], "type": "Metadata"}
    if is_metadata_content_present(f"{uri}/{metadata_key}", ctx, payload):
        ctx.obj.logger.info(f"{metadata_key} {metadata_value} in {dns_zone} already present.")
        utils.exit_action(
            ctx,
            success=True,
            message=f"{metadata_key}={metadata_value} in {dns_zone} already present.",
        )
    r = utils.http_post(uri, ctx, payload)
    if r.status_code == 201:
        ctx.obj.logger.info(
            f"Successfully added metadata {metadata_key}={metadata_value} to {dns_zone}."
        )
        utils.exit_action(
            ctx,
            success=True,
            message=f"Added metadata {metadata_key}={metadata_value} to {dns_zone}.",
            response=r,
        )
    else:
        ctx.obj.logger.error(
            f"Failed to add metadata {metadata_key}={metadata_value} to {dns_zone}."
        )
        utils.exit_action(
            ctx,
            success=False,
            message=f"Failed to add metadata {metadata_key}={metadata_value} to {dns_zone}.",
            response=r,
        )


@metadata.command(
    "delete",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@powerdns_zone
@click.argument("metadata-key", type=click.STRING)
@click.pass_context
def metadata_delete(ctx, dns_zone, metadata_key, **kwargs):
    """
    Deletes a metadata entry for the given zone.
    """
    uri = (
        f"{ctx.obj.config['apihost']}/api/v1/servers/"
        f"localhost/zones/{dns_zone}/metadata/{metadata_key}"
    )
    if not is_metadata_entry_present(uri, ctx):
        ctx.obj.logger.info(f"{metadata_key} for {dns_zone} already absent.")
        utils.exit_action(
            ctx, success=True, message=f"{metadata_key} for {dns_zone} already absent."
        )
    r = utils.http_delete(uri, ctx)
    if r.status_code in (204, 200):
        ctx.obj.logger.info(f"Deleted metadata key {metadata_key} for {dns_zone}.")
        utils.exit_action(
            ctx,
            success=True,
            message=f"Deleted metadata key {metadata_key} for {dns_zone}.",
            response=r,
        )
    else:
        ctx.obj.logger.error(f"Failed to delete metadata key {metadata_key} for {dns_zone}.")
        utils.exit_action(
            ctx,
            success=False,
            message=f"Failed to delete metadata key {metadata_key} for {dns_zone}.",
            response=r,
        )


@metadata.command(
    "extend",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@powerdns_zone
@click.argument("metadata-key", type=click.STRING)
@click.argument("metadata-value", type=click.STRING)
@click.pass_context
def metadata_extend(ctx, dns_zone, metadata_key, metadata_value, **kwargs):
    """
    Appends a new item to the list of metadata contents for a zone.
    """
    ctx.forward(metadata_add)


@metadata.command(
    "import",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@powerdns_zone
@click.argument("file", type=click.File())
@click.option(
    "--replace",
    type=click.BOOL,
    is_flag=True,
    help="Replace all metadata settings with new ones",
)
@click.option(
    "--ignore-errors",
    type=click.BOOL,
    is_flag=True,
    help="Continue import even when requests fail.",
)
@click.pass_context
def metadata_import(ctx, dns_zone, file, replace, ignore_errors, **kwargs) -> NoReturn:
    """Import metadata for a DNS zone from a file.

    File format:
    [{"kind": str, "metadata": list[str,...], "type": "Metadata"},...]
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/metadata"
    ctx.obj.logger.info(f"Importing metadata for zone: {dns_zone}.")
    settings = utils.extract_file(ctx, file)
    upstream_settings = utils.read_settings_from_upstream(uri, ctx)
    utils.validate_simple_import(ctx, settings, upstream_settings, replace)
    metadata_remove_soa_edit_api(settings, upstream_settings)
    if replace and upstream_settings:
        ctx.obj.logger.info("Replacing existing metadata.")
        replace_metadata_from_import(uri, ctx, upstream_settings, settings, ignore_errors)
    else:
        ctx.obj.logger.info("Adding new metadata.")
        add_metadata_from_import(uri, ctx, upstream_settings, settings, ignore_errors)


@metadata.command(
    "export",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@powerdns_zone
@click.option(
    "-l",
    "--limit",
    type=click.STRING,
    help="Limit metadata output to this single element.",
)
@click.pass_context
def metadata_export(ctx: click.Context, dns_zone: str, limit: str, **kwargs) -> NoReturn:
    """
    Exports the metadata for a given zone.
    Can optionally be limited to a single key.
    """
    ctx.obj.logger.info(f"Exporting metadata for zone: {dns_zone}, limit: {limit}.")
    if limit:
        uri = (
            f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/"
            f"zones/{dns_zone}/metadata/{limit}"
        )
    else:
        uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/metadata"
    utils.show_setting(ctx, uri, "metadata", "export")


@metadata.command("spec")
def metadata_spec():
    """Open the metadata specification on https://redocly.github.io."""
    utils.open_spec("metadata")


@metadata.command(
    "update",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@powerdns_zone
@click.argument("metadata-key", type=click.STRING)
@click.argument("metadata-value", type=click.STRING)
@click.pass_context
def metadata_update(
    ctx: click.Context, dns_zone: str, metadata_key: str, metadata_value: str, **kwargs
) -> NoReturn:
    """
    Replaces a set of metadata of a given zone.
    """
    uri = (
        f"{ctx.obj.config['apihost']}/api/v1/servers/"
        f"localhost/zones/{dns_zone}/metadata/{metadata_key}"
    )
    payload = {"kind": metadata_key, "metadata": [metadata_value], "type": "Metadata"}
    if not is_metadata_content_identical(uri, ctx, payload):
        r = utils.http_put(uri, ctx, payload)
        if r.status_code == 200:
            ctx.obj.logger.info(f"Metadata for {metadata_key} updated successfully.")
            utils.exit_action(
                ctx,
                success=True,
                message=f"Metadata for {metadata_key} updated successfully.",
                response=r,
            )
        else:
            ctx.obj.logger.error(f"Failed to update metadata for {metadata_key}.")
            utils.exit_action(
                ctx,
                success=False,
                message=f"Failed to update metadata for {metadata_key}.",
                response=r,
            )
    else:
        ctx.obj.logger.info(f"{metadata_key}:{metadata_value} for {dns_zone} already present.")
        utils.exit_action(
            ctx,
            success=True,
            message=f"{metadata_key}:{metadata_value} for {dns_zone} already present.",
        )


def metadata_remove_soa_edit_api(settings: dict, upstream_settings: dict) -> None:
    """
    Removes any entries with the kind 'SOA-EDIT-API' from settings and upstream_settings.
    The function iterates through both `settings` and `upstream_settings` to find and
    remove entries where the 'kind' key has the value 'SOA-EDIT-API'.
    This is done because 'SOA-EDIT-API' cannot be edited through the API and
    should not be present in the configuration.
    Args:
        settings: List of dictionaries from which 'SOA-EDIT-API' entries are removed.
        upstream_settings: List of dictionaries from which 'SOA-EDIT-API' entries are to be removed.
    Returns:
        None: This function modifies the input lists in place and does not return a value.
    """
    settings[:] = [item for item in settings if item.get("kind") != "SOA-EDIT-API"]
    upstream_settings[:] = [
        item for item in upstream_settings if item.get("kind") != "SOA-EDIT-API"
    ]


def replace_metadata_from_import(
    uri: str,
    ctx: click.Context,
    upstream_settings: list,
    settings: list,
    continue_on_error: bool = False,
) -> NoReturn:
    """Replaces metadata entries from an import, handling additions and deletions as needed.
    Args:
        uri: The base URI for API requests.
        ctx: Click context object for command-line operations.
        upstream_settings: List of dictionaries representing existing upstream metadata entries.
        settings: List of dictionaries representing desired metadata entries.
        continue_on_error: If True, continues execution after errors instead of aborting.
    """
    existing_upstreams = []
    upstreams_to_delete = []
    for metadata_entry in upstream_settings:
        if metadata_entry["kind"] == "SOA-EDIT-API":
            continue
        if metadata_entry in settings:
            existing_upstreams.append(metadata_entry)
        else:
            upstreams_to_delete.append(metadata_entry)
    for metadata_entry in settings:
        if metadata_entry not in existing_upstreams:
            ctx.obj.logger.info(f"Adding metadata entry: {metadata_entry['kind']}.")
            r = utils.http_post(uri, ctx, payload=metadata_entry)
            if r.status_code != 201:
                ctx.obj.logger.error(f"Failed adding {metadata_entry['kind']}.")
                if not continue_on_error:
                    utils.exit_action(ctx, False, f"Failed adding {metadata_entry['kind']}.", r)
    for metadata_entry in upstreams_to_delete:
        ctx.obj.logger.info(f"Deleting metadata entry: {metadata_entry['kind']}.")
        r = utils.http_delete(f"{uri}/{metadata_entry['kind']}", ctx)
        if r.status_code != 204:
            ctx.obj.logger.error(f"Failed deleting {metadata_entry['kind']}.")
            if not continue_on_error:
                utils.exit_action(ctx, False, f"Failed deleting {metadata_entry['kind']}.", r)
    utils.exit_action(ctx, True, "Successfully replaced metadata from file.")


def add_metadata_from_import(
    uri: str,
    ctx: click.Context,
    upstream_settings: list,
    settings: list,
    continue_on_error: bool = False,
) -> NoReturn:
    """Adds metadata entries from an import, updating existing entries if necessary.
    This function iterates through the provided settings, checks for existing metadata entries in
     `upstream_settings`, and either updates or adds them via an API call.
    Args:
        uri: The base URI for API requests.
        ctx: Click context object for command-line operations.
        upstream_settings: List of dictionaries representing existing upstream metadata entries.
        settings: List of dictionaries representing desired metadata entries to add or update.
        continue_on_error: If True, continues execution after errors instead of aborting.
    """
    for metadata_entry in settings:
        if metadata_entry["kind"] == "SOA-EDIT-API":
            continue
        payload = None
        for existing_metadata in upstream_settings:
            if metadata_entry["kind"] == existing_metadata["kind"]:
                payload = existing_metadata | metadata_entry
                break
        if not payload:
            payload = metadata_entry.copy()
        ctx.obj.logger.info(f"Adding/updating metadata entry: {payload['kind']}.")
        r = utils.http_post(uri, ctx, payload=payload)
        if r.status_code == 201:
            ctx.obj.logger.info(f"Successfully added/updated {payload['kind']}.")
        else:
            ctx.obj.logger.error(f"Failed adding/updating {payload['kind']}.")
            if not continue_on_error:
                utils.exit_action(ctx, False, f"Failed adding/updating {payload['kind']}.", r)
    utils.exit_action(ctx, True, "Successfully added metadata from file.")


def is_metadata_content_present(uri: str, ctx: click.Context, new_data: dict) -> bool:
    """Checks if an entry is already present in the metadata for the zone.
    This function verifies if the given metadata information exists in the corresponding list.
    Args:
        uri: The base URI for API requests.
        ctx: Click context object for command-line operations.
        new_data: Dictionary representing the metadata entry to check.
    Returns:
        bool: True if the metadata entry is present, False otherwise.
    """
    ctx.obj.logger.info(f"Checking if metadata entry {new_data['kind']} is present.")
    zone_metadata = utils.http_get(uri, ctx)
    if zone_metadata.status_code != 200:
        ctx.obj.logger.error("Failed to fetch zone metadata.")
        return False
    try:
        if (
            new_data["kind"] == zone_metadata.json()["kind"]
            and new_data["metadata"][0] in zone_metadata.json()["metadata"]
        ):
            ctx.obj.logger.info(f"Metadata entry {new_data['kind']} is already present.")
            return True
    except (KeyError, IndexError) as e:
        ctx.obj.logger.error(f"Error checking metadata: {e}.")
        return False
    ctx.obj.logger.info(f"Metadata entry {new_data['kind']} is not present.")
    return False


def is_metadata_content_identical(uri: str, ctx: click.Context, new_data: dict) -> bool:
    """Checks if the metadata entry is identical to the new content.
    Args:
        uri: The base URI for API requests.
        ctx: Click context object for command-line operations.
        new_data: Dictionary representing the metadata entry to compare.
    Returns:
        bool: True if the metadata entry is identical, False otherwise.
    """
    ctx.obj.logger.info(f"Checking if metadata entry is identical to {new_data['kind']}.")
    zone_metadata = utils.http_get(uri, ctx)
    if zone_metadata.status_code != 200:
        ctx.obj.logger.error("Failed to fetch zone metadata.")
        return False
    if new_data == zone_metadata.json():
        ctx.obj.logger.info(f"Metadata entry {new_data['kind']} is identical.")
        return True
    ctx.obj.logger.info(f"Metadata entry {new_data['kind']} is not identical.")
    return False


def is_metadata_entry_present(uri: str, ctx: click.Context) -> bool:
    """Checks if any metadata entry exists at the given URI.
    Args:
        uri: The base URI for API requests.
        ctx: Click context object for command-line operations.
    Returns:
        bool: True if metadata entries exist, False otherwise.
    """
    ctx.obj.logger.info("Checking if any metadata entry exists.")
    zone_metadata = utils.http_get(uri, ctx)
    if zone_metadata.status_code == 200 and zone_metadata.json().get("metadata"):
        ctx.obj.logger.info("Metadata entries exist.")
        return True
    ctx.obj.logger.info("No metadata entries exist.")
    return False
