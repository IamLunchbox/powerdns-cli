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

import click

from ..utils import main as utils
from ..utils.validation import PowerDNSZone


@click.group()
def metadata():
    """Set up metadata for a zone"""


@metadata.command("add")
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.argument("metadata-key", type=click.STRING)
@click.argument("metadata-value", type=click.STRING)
@click.pass_context
def metadata_add(ctx, dns_zone, metadata_key, metadata_value):
    """
    Adds metadata to a zone. Valid dictionary metadata-keys are not arbitrary and must conform
    to the expected content from the PowerDNS configuration. Custom metadata must be preceded by
    leading X- as a key
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/metadata"
    payload = {"kind": metadata_key, "metadata": [metadata_value], "type": "Metadata"}
    if is_metadata_content_present(f"{uri}/{metadata_key}", ctx, payload):
        utils.print_output(
            {"message": f"{metadata_key} {metadata_value} in {dns_zone} already present"}
        )
        raise SystemExit(0)
    r = utils.http_post(uri, ctx, payload)
    if utils.create_output(r, (201,)):
        raise SystemExit(0)
    raise SystemExit(1)


@metadata.command("delete")
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.argument("metadata-key", type=click.STRING)
@click.pass_context
def metadata_delete(ctx, dns_zone, metadata_key):
    """
    Deletes a metadata entry for the given zone.
    """
    uri = (
        f"{ctx.obj.config['apihost']}/api/v1/servers/"
        f"localhost/zones/{dns_zone}/metadata/{metadata_key}"
    )
    if is_metadata_entry_present(uri, ctx):
        r = utils.http_delete(uri, ctx)
        if utils.create_output(
            r,
            (204, 200),
            optional_json={"message": f"Deleted metadata key {metadata_key} for {dns_zone}"},
        ):
            raise SystemExit(0)
        raise SystemExit(1)
    utils.print_output({"message": f"{metadata_key} for {dns_zone} already absent"})
    raise SystemExit(0)


# pylint: disable=unused-argument
# noinspection PyUnusedLocal
@metadata.command("extend")
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.argument("metadata-key", type=click.STRING)
@click.argument("metadata-value", type=click.STRING)
@click.pass_context
def metadata_extend(ctx, dns_zone, metadata_key, metadata_value):
    """
    Appends a new item to the list of metadata item for a zone
    """
    ctx.forward(metadata_add)


# pylint: enable=unused-argument
@metadata.command("import")
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.argument("file", type=click.File())
@click.option(
    "--replace",
    type=click.BOOL,
    is_flag=True,
    help="Replace all metadata settings with new ones",
)
@click.option(
    "--ignore-errors", type=click.BOOL, is_flag=True, help="Continue import even when requests fail"
)
@click.pass_context
def metadata_import(ctx, dns_zone, file, replace, ignore_errors):
    """Import metadata for a DNS zone from a file."""
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/metadata"
    settings = utils.extract_file(file)
    upstream_settings = utils.read_settings_from_upstream(uri, ctx)
    utils.validate_simple_import(ctx, settings, upstream_settings, replace)
    metadata_remove_soa_edit_api(settings, upstream_settings)
    if replace and upstream_settings:
        replace_metadata_from_import(uri, ctx, upstream_settings, settings, ignore_errors)
    else:
        add_metadata_from_import(uri, ctx, upstream_settings, settings, ignore_errors)
    utils.print_output({"message": "Successfully imported metadata"})
    raise SystemExit(0)


@metadata.command("export")
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.option(
    "-l",
    "--limit",
    type=click.STRING,
    help="Limit metadata output to this single element",
)
@click.pass_context
def metadata_export(ctx, dns_zone, limit):
    """
    Lists the metadata for a given zone. Can optionally be limited to a single key.
    """
    if limit:
        uri = (
            f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/"
            f"zones/{dns_zone}/metadata/{limit}"
        )
    else:
        uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/" f"zones/{dns_zone}/metadata"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@metadata.command("spec")
def metadata_spec():
    """Open the metadata specification on https://redocly.github.io"""
    utils.open_spec("metadata")


@metadata.command("update")
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.argument("metadata-key", type=click.STRING)
@click.argument("metadata-value", type=click.STRING)
@click.pass_context
def metadata_update(ctx, dns_zone, metadata_key, metadata_value):
    """
    Replaces a set of metadata of a given zone
    """
    uri = (
        f"{ctx.obj.config['apihost']}/api/v1/servers/"
        f"localhost/zones/{dns_zone}/metadata/{metadata_key}"
    )
    payload = {"kind": metadata_key, "metadata": [metadata_value], "type": "Metadata"}
    if not is_metadata_content_identical(uri, ctx, payload):
        r = utils.http_put(uri, ctx, payload)
        if utils.create_output(r, (200,)):
            raise SystemExit(0)
        raise SystemExit(1)
    utils.print_output(
        {"message": f"{metadata_key}:{metadata_value} for {dns_zone} already present"}
    )
    raise SystemExit(0)


def metadata_remove_soa_edit_api(settings: dict, upstream_settings: dict) -> None:
    """
    Removes any entries with the kind 'SOA-EDIT-API' from settings and upstream_settings.

    The function iterates through both `settings` and `upstream_settings` to find and remove
    entries where the 'kind' key has the value 'SOA-EDIT-API'. This is done because 'SOA-EDIT-API'
    cannot be edited through the api and should not be present in the configuration.

    Args:
        settings (dict): Dictionary from which 'SOA-EDIT-API' entries are to be removed.
        upstream_settings (dict): Upstream settings from which 'SOA-EDIT-API' entries are removed.

    Returns:
        None: This function modifies the input dictionaries in place and does not return a value.

    """
    if "SOA-EDIT-API" in [item["kind"] for item in settings]:
        dict_entry = [item for item in settings if item["kind"] == "SOA-EDIT-API"]
        position = settings.index(dict_entry[0])
        settings.pop(position)
    if "SOA-EDIT-API" in [item["kind"] for item in upstream_settings]:
        dict_entry = [item for item in upstream_settings if item["kind"] == "SOA-EDIT-API"][0]
        position = upstream_settings.index(dict_entry)
        upstream_settings.pop(position)


def replace_metadata_from_import(
    uri: str,
    ctx: click.Context,
    upstream_settings: list,
    settings: list,
    continue_on_error: bool = False,
) -> None:
    """Replaces metadata entries from an import, handling additions and deletions as needed.

    This function compares upstream settings with the provided settings list, adds new entries,
    and deletes obsolete ones. It aborts on errors unless `continue_on_error` is True.

    Args:
        uri: The base URI for API requests.
        ctx: Click context object for command-line operations.
        upstream_settings: List of dictionaries representing existing upstream metadata entries.
        settings: List of dictionaries representing desired metadata entries.
        continue_on_error: If True, continues execution after errors instead of aborting.
                           Defaults to False.

    Raises:
        SystemExit: If an error occurs during addition or deletion of metadata entries,
                   unless `continue_on_error` is True.
    """
    existing_upstreams = []
    upstreams_to_delete = []
    for metadata_entry in upstream_settings:
        if metadata_entry["kind"] == "SOA_EDIT_API":
            continue
        if metadata_entry in settings:
            existing_upstreams.append(metadata_entry)
        else:
            upstreams_to_delete.append(metadata_entry)
    for metadata_entry in settings:
        if metadata_entry not in existing_upstreams:
            r = utils.http_post(uri, ctx, payload=metadata_entry)
            if not r.status_code == 201:
                utils.handle_import_early_exit(
                    ctx,
                    "Failed adding {metadata_entry['kind']}",
                    continue_on_error,
                )
    for metadata_entry in upstreams_to_delete:
        r = utils.http_delete(f"{uri}/{metadata_entry['kind']}", ctx)
        if r.status_code != 204:
            utils.handle_import_early_exit(
                ctx,
                f"Failed deleting metadata {metadata_entry['kind']}",
                continue_on_error,
            )


def add_metadata_from_import(
    uri: str,
    ctx: click.Context,
    upstream_settings: list,
    settings: list,
    continue_on_error: bool = False,
) -> None:
    """Adds metadata entries from an import, updating existing entries if necessary.

    This function iterates through the provided settings, checks for existing metadata entries
    in `upstream_settings`, and either updates or adds them via an API call. If an error occurs,
    it aborts unless `continue_on_error` is True.

    Args:
        uri: The base URI for API requests.
        ctx: Click context object for command-line operations.
        upstream_settings: List of dictionaries representing existing upstream metadata entries.
        settings: List of dictionaries representing desired metadata entries to add or update.
        continue_on_error: If True, continues execution after errors instead of aborting.
                           Defaults to False.

    Raises:
        SystemExit: If an error occurs during the addition or update of metadata entries,
                   unless `continue_on_error` is True.
    """
    for metadata_entry in settings:
        if metadata_entry["kind"] == "SOA-EDIT-API":
            continue
        payload = None
        for existing_metadata in upstream_settings:
            if metadata_entry["kind"] == existing_metadata["kind"]:
                payload = existing_metadata.copy()
                payload.update(metadata_entry)
        if not payload:
            payload = metadata_entry.copy()
        r = utils.http_post(uri, ctx, payload=payload)
        if r.status_code != 201:
            utils.handle_import_early_exit(
                ctx,
                f"Failed adding metadata {payload['kind']}",
                continue_on_error,
            )


def is_metadata_content_present(uri: str, ctx: click.Context, new_data: dict) -> bool:
    """Checks if an entry is already existing in the metadata for the zone. Will not check
    for identical entries, only if the given metadata information is in the corresponding list
    """
    zone_metadata = utils.http_get(uri, ctx)
    if zone_metadata.status_code != 200:
        return False
    if (
        new_data["kind"] == zone_metadata.json()["kind"]
        and new_data["metadata"][0] in zone_metadata.json()["metadata"]
    ):
        return True
    return False


def is_metadata_content_identical(uri: str, ctx: click.Context, new_data: dict) -> bool:
    """Checks if the metadata entry is identical to the new content"""
    zone_metadata = utils.http_get(uri, ctx)
    if zone_metadata.status_code != 200:
        return False
    if new_data == zone_metadata.json():
        return True
    return False


def is_metadata_entry_present(uri: str, ctx: click.Context) -> bool:
    """Checks if a metadata entry exists at all"""
    zone_metadata = utils.http_get(uri, ctx)
    # When there is no metadata set of the given type, the api will still
    # return 200 and a dict with an emtpy list of metadata entries
    if zone_metadata.status_code == 200 and zone_metadata.json()["metadata"]:
        return True
    return False
