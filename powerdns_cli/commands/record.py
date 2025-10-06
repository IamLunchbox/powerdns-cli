"""
A Click-based CLI module for managing DNS resource records (RRsets) in PowerDNS.

This module provides a comprehensive set of commands for managing DNS resource records.

Commands:
    add: Adds a new DNS record to a zone.
    delete: Deletes a DNS record from a zone, optionally all records of a type.
    enable: Enables a previously disabled DNS record.
    disable: Disables an existing DNS record.
    extend: Extends an existing RRSET with a new record.
    export: Exports DNS records for a zone, optionally filtered by name or type.
    import: Imports DNS records from a file into a zone.
    spec: Opens the DNS record API specification in the browser.
"""

from typing import Any

import click

from ..utils import main as utils
from ..utils.validation import PowerDNSZone


@click.group()
def record():
    """Resource records of a zone"""


@record.command("add")
@click.argument("name", type=click.STRING)
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.argument(
    "record-type",
    type=click.Choice(
        [
            "A",
            "AAAA",
            "CNAME",
            "MX",
            "NS",
            "PTR",
            "SOA",
            "SRV",
            "TXT",
        ],
        case_sensitive=False,
    ),
)
@click.argument("content", type=click.STRING)
@click.option("--ttl", default=86400, type=click.INT, help="Set time to live")
@click.pass_context
def record_add(
    ctx,
    name,
    record_type,
    content,
    dns_zone,
    ttl,
):
    """
    Adds a new dns record of your given type. Use @ if you want to enter a
    record for the top level name / zone name
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}"
    name = utils.make_dnsname(name, dns_zone)
    rrset = {
        "name": name,
        "type": record_type.upper(),
        "ttl": ttl,
        "changetype": "REPLACE",
        "records": [{"content": content, "disabled": False}],
    }
    if is_content_present(uri, ctx, rrset):
        utils.print_output({"message": f"{name} {record_type} {content} already present"})
        raise SystemExit(0)

    r = utils.http_patch(uri, ctx, {"rrsets": [rrset]})
    if utils.create_output(
        r, (204,), optional_json={"message": f"{name} {record_type} {content} created"}
    ):
        raise SystemExit(0)
    raise SystemExit(1)


@record.command("delete")
@click.argument("name", type=click.STRING)
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.argument(
    "record-type",
    type=click.Choice(
        [
            "A",
            "AAAA",
            "CNAME",
            "MX",
            "NS",
            "PTR",
            "SOA",
            "SRV",
            "TXT",
        ],
        case_sensitive=False,
    ),
)
@click.argument("content", type=click.STRING)
@click.option("--ttl", default=86400, type=click.INT, help="Set default time to live")
@click.option(
    "-a",
    "--all",
    "delete_all",
    is_flag=True,
    default=False,
    help="Deletes all records of the selected type",
)
@click.pass_context
def record_delete(ctx, name, dns_zone, record_type, content, ttl, delete_all):
    """
    Deletes a record of the precisely given type and content.
    When there are two records, only the specified one will be removed,
    unless --all is provided.
    """
    name = utils.make_dnsname(name, dns_zone)
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}"
    if delete_all:
        rrset = {
            "name": name,
            "type": record_type.upper(),
            "ttl": ttl,
            "changetype": "DELETE",
            "records": [],
        }
        if not is_matching_rrset_present(uri, ctx, rrset):
            utils.print_output({"message": f"{record_type} records in {name} already absent"})
            raise SystemExit(0)
        r = utils.http_patch(uri, ctx, {"rrsets": [rrset]})
        msg = {"message": f"All {record_type} records for {name} removed"}
        if utils.create_output(r, (204,), optional_json=msg):
            raise SystemExit(0)
        utils.print_output({"message": f"Failed to delete all {record_type} records for {name}"})
        raise SystemExit(1)

    rrset = {
        "name": name,
        "type": record_type,
        "ttl": ttl,
        "changetype": "REPLACE",
        "records": [
            {
                "content": content,
                "disabled": False,
            }
        ],
    }
    if not is_content_present(uri, ctx, rrset):
        utils.print_output({"message": f"{name} {record_type} {content} already absent"})
        raise SystemExit(0)
    matching_rrsets = is_matching_rrset_present(uri, ctx, rrset)
    indizes_to_remove = []
    for index in range(len(matching_rrsets["records"])):
        if matching_rrsets["records"][index] == rrset["records"][0]:
            indizes_to_remove.append(index)
    indizes_to_remove.reverse()
    for index in indizes_to_remove:
        matching_rrsets["records"].pop(index)
    rrset["records"] = matching_rrsets["records"]
    r = utils.http_patch(uri, ctx, {"rrsets": [rrset]})
    msg = {"message": f"{name} {record_type} {content} removed"}
    if utils.create_output(r, (204,), optional_json=msg):
        raise SystemExit(0)
    raise SystemExit(1)


@record.command("disable")
@click.argument("name", type=click.STRING)
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.argument(
    "record-type",
    type=click.Choice(
        [
            "A",
            "AAAA",
            "CNAME",
            "MX",
            "NS",
            "PTR",
            "SOA",
            "SRV",
            "TXT",
        ],
        case_sensitive=False,
    ),
)
@click.argument("content", type=click.STRING)
@click.option("--ttl", default=86400, type=click.INT, help="Set time to live")
@click.pass_context
def record_disable(
    ctx,
    name,
    record_type,
    content,
    dns_zone,
    ttl,
):
    """
    Disables an existing dns record. Use @ to target the zone name itself
    """
    name = utils.make_dnsname(name, dns_zone)
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}"

    rrset = {
        "name": name,
        "type": record_type.upper(),
        "ttl": ttl,
        "changetype": "REPLACE",
        "records": [{"content": content, "disabled": True}],
    }

    if is_content_present(uri, ctx, rrset):
        utils.print_output({"message": f"{name} IN {record_type} {content} already disabled"})
        raise SystemExit(0)
    rrset["records"] = merge_rrsets(uri, ctx, rrset)
    r = utils.http_patch(uri, ctx, {"rrsets": [rrset]})
    msg = {"message": f"{name} IN {record_type} {content} disabled"}
    if utils.create_output(r, (204,), optional_json=msg):
        raise SystemExit(0)
    raise SystemExit(1)


# pylint: disable=unused-argument
@record.command("enable")
@click.argument("name", type=click.STRING)
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.argument(
    "record-type",
    type=click.Choice(
        [
            "A",
            "AAAA",
            "CNAME",
            "MX",
            "NS",
            "PTR",
            "SOA",
            "SRV",
            "TXT",
        ],
        case_sensitive=False,
    ),
)
@click.argument("content", type=click.STRING)
@click.option("--ttl", default=86400, type=click.INT, help="Set default time to live")
@click.pass_context
def record_enable(
    ctx,
    name,
    record_type,
    content,
    dns_zone,
    ttl,
):
    """Enable a dns-recordset. Does not check if it was disabled beforehand"""
    ctx.forward(record_add)


# pylint: enable=unused-argument


@record.command("extend")
@click.argument("name", type=click.STRING)
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.argument(
    "record-type",
    type=click.Choice(
        [
            "A",
            "AAAA",
            "CNAME",
            "MX",
            "NS",
            "PTR",
            "SOA",
            "SRV",
            "TXT",
        ],
        case_sensitive=False,
    ),
)
@click.argument("content", type=click.STRING)
@click.option("--ttl", default=86400, type=click.INT, help="Set time to live")
@click.pass_context
def record_extend(
    ctx,
    name,
    record_type,
    content,
    dns_zone,
    ttl,
):
    """
    Extends records of an existing RRSET. Will create a new RRSET, if it did not exist beforehand
    """
    name = utils.make_dnsname(name, dns_zone)
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}"

    rrset = {
        "name": name,
        "type": record_type.upper(),
        "ttl": ttl,
        "changetype": "REPLACE",
        "records": [{"content": content, "disabled": False}],
    }
    if is_content_present(uri, ctx, rrset):
        utils.print_output({"message": f"{name} IN {record_type} {content} already present"})
        raise SystemExit(0)
    upstream_rrset = is_matching_rrset_present(uri, ctx, rrset)
    if upstream_rrset:
        extra_records = [
            item
            for item in upstream_rrset["records"]
            if item["content"] != rrset["records"][0]["content"]
        ]
        rrset["records"].extend(extra_records)
    r = utils.http_patch(uri, ctx, {"rrsets": [rrset]})
    msg = {"message": f"{name} IN {record_type} {content} extended"}
    if utils.create_output(r, (204,), optional_json=msg):
        raise SystemExit(0)
    raise SystemExit(1)


@record.command("export")
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.option("--name", help="Limit output to chosen names", type=click.STRING)
@click.option(
    "record_type",
    "--type",
    help="Limit output to chosen record types",
    type=click.Choice(
        [
            "A",
            "AAAA",
            "CNAME",
            "MX",
            "NS",
            "PTR",
            "SOA",
            "SRV",
            "TXT",
        ],
        case_sensitive=False,
    ),
)
@click.pass_context
def record_export(
    ctx,
    name,
    record_type,
    dns_zone,
):
    """
    Exports the contents of an existing RRSET.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}"
    if name:
        name = utils.make_dnsname(name, dns_zone)
    rrsets = query_zone_rrsets(uri, ctx)
    output_list = []
    for rrset in rrsets:
        if rrset["name"] == name and rrset["type"] == record_type:
            output_list.append(rrset)
        elif rrset["name"] == name:
            output_list.append(rrset)
        elif rrset["type"] == record_type:
            output_list.append(rrset)
    if not output_list and not any((name, record_type)):
        output_list = rrsets
    utils.print_output(output_list)
    raise SystemExit(0)


@record.command("import")
@click.argument("file", type=click.File())
@click.option(
    "--replace",
    type=click.BOOL,
    is_flag=True,
    default=False,
    help="Replace old settings with new ones",
)
@click.pass_context
def record_import(ctx, file, replace):
    """
    Imports a rrset into a zone.
    Imported as a dictionary: {'id':str, 'rrsets':[]}, all other keys are ignored.
    'name' substitutes 'id'.
    """
    new_rrsets = utils.extract_file(file)
    validate_rrset_import(new_rrsets)
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{new_rrsets['id']}"
    # This function skips the usual deduplication logic from utils.import_settings, since
    # any patch request automatically extends existing rrsets (except where type and name matches,
    # those get replaced
    upstream_zone = utils.read_settings_from_upstream(uri, ctx)
    if not upstream_zone:
        upstream_zone["rrsets"] = []
    check_records_for_identical_content(new_rrsets, upstream_zone, replace)
    for rrset in new_rrsets["rrsets"]:
        rrset["changetype"] = "REPLACE"
    if replace:
        final_recordset = []
        final_recordset.extend(new_rrsets["rrsets"])
        new_rrset_types = [(item["name"], item["type"]) for item in new_rrsets["rrsets"]]
        upstream_rrset_types = [(item["name"], item["type"]) for item in upstream_zone["rrsets"]]
        for rrset_type in upstream_rrset_types:
            if rrset_type not in new_rrset_types:
                index = [
                    upstream_zone["rrsets"].index(item)
                    for item in upstream_zone["rrsets"]
                    if (item["name"], item["type"]) == rrset_type
                ][0]
                new_entry = upstream_zone["rrsets"][index] | {"changetype": "DELETE"}
                del new_entry["ttl"]
                del new_entry["records"]
                del new_entry["comments"]
                final_recordset.append(new_entry)
        new_rrsets["rrsets"] = final_recordset
    r = utils.http_patch(uri, ctx, payload=new_rrsets)
    if utils.create_output(r, (204,), optional_json={"message": "RRset imported"}):
        raise SystemExit(0)
    raise SystemExit(1)


@record.command("spec")
def record_spec():
    """Open the record specification on https://redocly.github.io"""
    utils.open_spec("record")


def check_records_for_identical_content(
    new_rrsets: dict[str, Any],
    upstream_zone: dict[str, Any],
    replace: bool,
) -> None:
    """
    Check if the new RRsets are already present in the upstream zone.

    This function compares the contents of new RRsets with those in the upstream zone,
    ignoring the 'modified_at' field. If all RRsets are already present, it prints a message
    and exits with status 0.

    Args:
        new_rrsets: A dictionary containing the new RRsets to check.
                    Expected to have a 'rrsets' key with a list of RRset dictionaries.
        upstream_zone: A dictionary containing the upstream zone RRsets.
                       Expected to have a 'rrsets' key with a list of RRset dictionaries.
        replace: If True, checks for exact match in both content and count.
                 If False, only checks if all new RRsets are present in the upstream zone.

    Raises:
        SystemExit: Exits with status 0 if the RRsets are already present.
    """

    def _normalize_rrset(rrset: dict[str, Any]) -> tuple[str, str, list[dict[str, Any]], int]:
        """Helper to normalize an RRset by removing 'modified_at' from records."""
        name, rrtype, records, ttl = (
            rrset["name"],
            rrset["type"],
            rrset["records"],
            rrset["ttl"],
        )
        normalized_records = [
            {k: v for k, v in record_item.items() if k != "modified_at"} for record_item in records
        ]
        return name, rrtype, normalized_records, ttl

    # Normalize both sets of RRsets
    new_rrset_contents = [_normalize_rrset(item) for item in new_rrsets["rrsets"]]
    upstream_rrset_contents = [_normalize_rrset(item) for item in upstream_zone["rrsets"]]

    # Check for presence of all new RRsets in upstream
    if not replace and all(rrset in upstream_rrset_contents for rrset in new_rrset_contents):
        utils.print_output({"message": "Requested rrsets are already present"})
        raise SystemExit(0)

    # Check for exact match if replace is True
    if replace and (
        all(rrset in upstream_rrset_contents for rrset in new_rrset_contents)
        and len(upstream_rrset_contents) == len(new_rrset_contents)
    ):
        utils.print_output({"message": "Requested rrsets are already present"})
        raise SystemExit(0)


def validate_rrset_import(rrset: dict) -> None:
    """
    Validates the structure and content of a rrset dictionary for import.

    Args:
        rrset: A dictionary representing the rrset to validate.
            Expected to contain 'rrsets' and either 'id' or 'name'.

    Raises:
        SystemExit: Exits with status 1 if validation fails.
    """
    if not isinstance(rrset, dict):
        utils.print_output({"error": "You must supply rrsets as a single dictionary"})
        raise SystemExit(1)

    if not rrset.get("rrsets"):
        utils.print_output({"error": "The key 'rrsets' must be present."})
        raise SystemExit(1)

    if not rrset.get("id") and not rrset.get("name"):
        utils.print_output({"error": "Either 'name' or 'id' must be present to determine the zone"})
        raise SystemExit(1)

    if rrset.get("name") and not rrset.get("id"):
        rrset["id"] = rrset["name"]

    for key in list(rrset.keys()):
        if key not in ("id", "rrsets"):
            del rrset[key]


def replace_rrset_import(
    uri: str,
    ctx: click.Context,
    settings: list,
    upstream_settings: list,
    setting_names: list,
    ignore_errors: bool,
) -> None:
    """
    Replace RRset zones by removing existing ones and adding new configurations.

    Args:
        uri: API endpoint URI
        ctx: Click context object
        settings: List of new zone configurations to import
        upstream_settings: List of existing upstream zone configurations
        setting_names: Set of zone names from the new settings
        ignore_errors: If True, continue processing despite errors
    """
    existing_upstreams = []
    upstreams_to_delete = []
    for zone_entry in upstream_settings:
        if zone_entry["name"] in setting_names:
            existing_upstreams.append(zone_entry)
        else:
            upstreams_to_delete.append(zone_entry)
    for zone_entry in settings:
        if zone_entry["name"] in [upstream["name"] for upstream in existing_upstreams]:
            r = utils.http_delete(f"{uri}/{zone_entry['name']}", ctx)
            if r.status_code != 204:
                utils.handle_import_early_exit(
                    ctx,
                    "An error occoured deleting the zone, aborting further changes",
                    ignore_errors,
                )

        r = utils.http_post(uri, ctx, payload=zone_entry)
        if r.status_code != 201:
            utils.handle_import_early_exit(
                ctx,
                f"Failed adding rrset {zone_entry['name']}",
                ignore_errors,
            )

    for zone_entry in upstreams_to_delete:
        r = utils.http_delete(f"{uri}/{zone_entry['name']}", ctx)
        if r.status_code != 204:
            utils.handle_import_early_exit(
                ctx,
                f"Failed deleting rrset {zone_entry['name']}",
                ignore_errors,
            )


def merge_rrsets(uri: str, ctx: click.Context, new_rrset: dict) -> list:
    """Merge the upstream and local rrset records to create a unified and deduplicated set"""
    zone_rrsets = query_zone_rrsets(uri, ctx)
    merged_rrsets = new_rrset["records"].copy()
    for upstream_rrset in zone_rrsets:
        if all(upstream_rrset[key] == new_rrset[key] for key in ("name", "type")):
            merged_rrsets.extend(
                [
                    record_item
                    for record_item in upstream_rrset["records"]
                    if record_item["content"] != new_rrset["records"][0]["content"]
                ]
            )
    return merged_rrsets


def is_matching_rrset_present(uri: str, ctx: click.Context, new_rrset: dict) -> dict:
    """Checks if a RRSETs is already existing in the dns database, does not check records"""
    zone_rrsets = query_zone_rrsets(uri, ctx)
    for upstream_rrset in zone_rrsets:
        if all(upstream_rrset[key] == new_rrset[key] for key in ("name", "type")):
            return upstream_rrset
    return {}


def query_zone_rrsets(uri: str, ctx) -> list[dict]:
    """Queries the configuration of the given zone and returns a list of all RRSETs.

    Sends a GET request to the specified `uri` to fetch the zone's RRSETs.
    If response status is not 200, it prints the error response and exits with a status code of 1.
    Otherwise, it returns the list of RRSETs from the JSON response.

    Args:
        uri (str): The URI to query for the zone's RRSETs.
        ctx (click.Context): Click context object for command-line operations.

    Returns:
        list[dict]: A list of dictionaries, where each dictionary represents an RRSET.

    Raises:
        SystemExit: If the request to fetch RRSETs fails (non-200 status code).
    """
    r = utils.http_get(uri, ctx)
    if r.status_code != 200:
        utils.print_output(r.json())
        raise SystemExit(1)
    return r.json()["rrsets"]


def is_content_present(uri: str, ctx: click.Context, new_rrset: dict) -> bool:
    """Checks if a matching rrset is present and if the new record is also already present"""
    zone_rrsets = query_zone_rrsets(uri, ctx)
    for rrset in zone_rrsets:
        if (
            # Check if general entry name, type and ttl are the same
            all(rrset[key] == new_rrset[key] for key in ("name", "type", "ttl"))
            and
            # Check if all references within that rrset are identical
            all(record_item in rrset["records"] for record_item in new_rrset["records"])
        ):
            return True
    return False
