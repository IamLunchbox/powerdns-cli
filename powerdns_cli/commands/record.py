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

from typing import Any, NoReturn, TextIO

import click

from ..utils import main as utils
from ..utils.validation import DefaultCommand, powerdns_zone


@click.group()
def record():
    """Edit resource records (RRSets) of a zone.
    This action enables changing RRSets of a zone without the necessity (and danger)
    of specifying additional zone data. It is not possible to only change the ttl of a RRSet.
    To do this, it is required to remove and readd a RRSet. But facilitating the export and import
    function may prove useful.
    By default, the add action will replace the current content of the RRSet. For example:
    www.example.com in A 127.0.0.1
    www.example.com in A 127.0.0.2
    will be replaced with powerdns-cli record add www example.com A 10.0.0.1 to:
    www.example.com in A 10.0.0.1.
    """


@record.command(
    "add",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.argument("name", type=click.STRING)
@powerdns_zone
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
@click.argument("value", type=click.STRING)
@click.option("--ttl", default=86400, type=click.INT, help="Set time to live.")
@click.pass_context
def record_add(
    ctx: click.Context, name: str, dns_zone: str, record_type: str, value: str, ttl: int, **kwargs
) -> NoReturn:
    """
    Adds a new DNS record of your given type. Use @ if you want to enter a
    record for the top level name / zone name.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}"
    name = utils.make_dnsname(name, dns_zone)
    rrset = {
        "name": name,
        "type": record_type.upper(),
        "ttl": ttl,
        "changetype": "REPLACE",
        "records": [{"content": value, "disabled": False}],
    }
    if is_value_present(uri, ctx, rrset):
        ctx.obj.logger.info(f"{name} {record_type} {value} already present.")
        utils.exit_action(ctx, True, f"{name} {record_type} {value} already present.")
    r = utils.http_patch(uri, ctx, {"rrsets": [rrset]})
    if r.status_code == 204:
        ctx.obj.logger.info(f"{name} {record_type} {value} created.")
        utils.exit_action(ctx, True, f"{name} {record_type} {value} created.", r)
    else:
        ctx.obj.logger.error(f"Failed to create {name} {record_type} {value}.")
        utils.exit_action(ctx, False, f"Failed to create {name} {record_type} {value}.", r)


@record.command(
    "delete",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.pass_context
@click.argument("name", type=click.STRING)
@powerdns_zone
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
@click.argument("value", type=click.STRING)
@click.option("--ttl", default=86400, type=click.INT, help="Set default time to live.")
@click.option(
    "--all",
    "delete_all",
    is_flag=True,
    default=False,
    help="Deletes all records of the selected type.",
)
def record_delete(
    ctx: click.Context,
    name: str,
    dns_zone: str,
    record_type: str,
    value: str,
    ttl: int,
    delete_all: bool,
    **kwargs,
) -> NoReturn:
    """
    Deletes a record of the precisely given type and value.
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
            ctx.obj.logger.info(f"{record_type} records in {name} already absent.")
            utils.exit_action(ctx, True, f"{record_type} records in {name} already absent.")
        r = utils.http_patch(uri, ctx, {"rrsets": [rrset]})
        if r.status_code == 204:
            ctx.obj.logger.info(f"All {record_type} records for {name} removed.")
            utils.exit_action(ctx, True, f"All {record_type} records for {name} removed.", r)
        else:
            ctx.obj.logger.error(f"Failed to delete all {record_type} records for {name}.")
            utils.exit_action(
                ctx, False, f"Failed to delete all {record_type} records for {name}.", r
            )
    rrset = {
        "name": name,
        "type": record_type.upper(),
        "ttl": ttl,
        "changetype": "REPLACE",
        "records": [{"content": value, "disabled": False}],
    }
    if not is_value_present(uri, ctx, rrset):
        ctx.obj.logger.warning(f"{name} {record_type} {value} already absent.")
        utils.exit_action(
            ctx, success=True, message=f"{name} {record_type} {value} already absent."
        )
    matching_rrsets = is_matching_rrset_present(uri, ctx, rrset)
    indices_to_remove = [
        index
        for index, rrset_entry in enumerate(matching_rrsets["records"])
        if rrset_entry == rrset["records"][0]
    ]
    indices_to_remove.reverse()
    for index in indices_to_remove:
        matching_rrsets["records"].pop(index)
    rrset["records"] = matching_rrsets["records"]
    r = utils.http_patch(uri, ctx, {"rrsets": [rrset]})
    if r.status_code == 204:
        ctx.obj.logger.info(f"{name} {record_type} {value} removed.")
        utils.exit_action(ctx, True, f"{name} {record_type} {value} removed.", r)
    else:
        ctx.obj.logger.error(f"Failed to remove {name} {record_type} {value}.")
        utils.exit_action(ctx, False, f"Failed to remove {name} {record_type} {value}.", r)


@record.command(
    "disable",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.argument("name", type=click.STRING)
@powerdns_zone
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
@click.argument("value", type=click.STRING)
@click.option("--ttl", default=86400, type=click.INT, help="Set time to live.")
@click.pass_context
def record_disable(
    ctx: click.Context, name: str, dns_zone: str, record_type: str, value: str, ttl: int, **kwargs
) -> NoReturn:
    """
    Disables an existing DNS record. Use @ to target the zone name itself.
    """
    name = utils.make_dnsname(name, dns_zone)
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}"
    rrset = {
        "name": name,
        "type": record_type.upper(),
        "ttl": ttl,
        "changetype": "REPLACE",
        "records": [{"content": value, "disabled": True}],
    }
    if is_value_present(uri, ctx, rrset):
        ctx.obj.logger.warning(f"{name} IN {record_type} {value} already disabled.")
        utils.exit_action(ctx, True, f"{name} IN {record_type} {value} already disabled.")
    rrset["records"] = merge_rrsets(uri, ctx, rrset)
    r = utils.http_patch(uri, ctx, {"rrsets": [rrset]})
    if r.status_code == 204:
        ctx.obj.logger.info(f"{name} IN {record_type} {value} disabled.")
        utils.exit_action(ctx, True, f"{name} IN {record_type} {value} disabled.", r)
    else:
        ctx.obj.logger.error(f"Failed to disable {name} IN {record_type} {value}.")
        utils.exit_action(ctx, False, f"Failed to disable {name} IN {record_type} {value}.", r)


@record.command(
    "enable",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.argument("name", type=click.STRING)
@powerdns_zone
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
@click.argument("value", type=click.STRING)
@click.option("--ttl", default=86400, type=click.INT, help="Set default time to live.")
@click.pass_context
def record_enable(
    ctx: click.Context, name: str, dns_zone: str, record_type: str, value: str, ttl: int, **kwargs
) -> NoReturn:
    """Enable a dns-recordset. Does not check if it was disabled beforehand."""
    ctx.forward(record_add)


@record.command(
    "extend",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.argument("name", type=click.STRING)
@powerdns_zone
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
@click.argument("value", type=click.STRING)
@click.option("--ttl", default=86400, type=click.INT, help="Set time to live.")
@click.pass_context
def record_extend(
    ctx: click.Context, name: str, dns_zone: str, record_type: str, value: str, ttl: int, **kwargs
) -> NoReturn:
    """
    Extends records of an existing RRSET. Will create a new RRSET, if it did not exist beforehand.
    """
    name = utils.make_dnsname(name, dns_zone)
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}"
    rrset = {
        "name": name,
        "type": record_type.upper(),
        "ttl": ttl,
        "changetype": "REPLACE",
        "records": [{"content": value, "disabled": False}],
    }
    if is_value_present(uri, ctx, rrset):
        ctx.obj.logger.info(f"{name} IN {record_type} {value} already present.")
        utils.exit_action(ctx, True, f"{name} IN {record_type} {value} already present.")
    upstream_rrset = is_matching_rrset_present(uri, ctx, rrset)
    if upstream_rrset:
        extra_records = [
            item
            for item in upstream_rrset["records"]
            if item["content"] != rrset["records"][0]["content"]
        ]
        rrset["records"].extend(extra_records)
    r = utils.http_patch(uri, ctx, {"rrsets": [rrset]})
    if r.status_code == 204:
        ctx.obj.logger.info(f"Successfully extended {name} IN {record_type} with {value}.")
        utils.exit_action(
            ctx, True, f"Successfully extended {name} IN {record_type} with {value}.", r
        )
    else:
        ctx.obj.logger.error(f"Failed to extend {name} IN {record_type} {value}.")
        utils.exit_action(ctx, False, f"Failed to extend {name} IN {record_type} {value}.", r)


@record.command(
    "export",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@powerdns_zone
@click.option("--bind", "-b", help="Print all records in bind format.", is_flag=True)
@click.option("--name", help="Limit output to chosen names.", type=click.STRING)
@click.option(
    "record_type",
    "--type",
    help="Limit output to chosen record types.",
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
    ctx: click.Context, dns_zone: str, bind: bool, name: str, record_type: str, **kwargs
) -> NoReturn:
    """
    Exports the contents of a single or all existing RRSets.
    """
    if bind:
        ctx.obj.logger.info(f"Exporting {dns_zone} in BIND format.")
        uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/export"
        r = utils.http_get(uri, ctx)
        if r.status_code == 200:
            ctx.obj.handler.set_message(r.text)
            ctx.obj.handler.set_data(r)
            ctx.obj.handler.set_success()
            utils.exit_cli(ctx)
        elif r.status_code == 404:
            ctx.obj.handler.set_message(f"Failed exporting {dns_zone}, not found.")
            ctx.obj.handler.set_success(False)
            utils.exit_cli(ctx)
        ctx.obj.handler.set_message(f"Failed exporting {dns_zone}, unknown error.")
        ctx.obj.handler.set_success(False)
        utils.exit_cli(ctx)
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
    output_with_id = {"id": dns_zone, "rrsets": output_list}
    ctx.obj.handler.result["data"] = output_with_id
    utils.exit_action(ctx, True, "Successfully exported records.", print_data=True)


@record.command(
    "import",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.argument("file", type=click.File())
@click.option(
    "--replace",
    is_flag=True,
    help="Replace old settings with new ones.",
)
@click.pass_context
def record_import(ctx: click.Context, file: TextIO, replace: bool, **kwargs) -> NoReturn:
    """
    Imports a rrset into a zone.
    All keys besides name, id and rrsets are ignored.
    'name' substitutes 'id', when 'id' is unset.
    You may use - to declare the input as STDIN.
    File format:
    {"id":str,
    "rrsets":[
    {"comments": list[str,...], "name": str,"records": [
    {"content": str, "disabled": bool},...],
    "ttl": int,"type": str},...
    ]
    }
    """
    new_rrsets = utils.extract_file(ctx, file)
    validate_rrset_import(ctx, new_rrsets)
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/zones/{new_rrsets['id']}"
    upstream_zone = utils.read_settings_from_upstream(uri, ctx)
    if not upstream_zone:
        upstream_zone["rrsets"] = []
    check_records_for_identical_content(ctx, new_rrsets, upstream_zone, replace)
    for rrset in new_rrsets["rrsets"]:
        rrset["changetype"] = "REPLACE"
    if replace:
        ctx.obj.logger.info("Replace flag enabled; preparing final recordset.")
        final_recordset = []
        final_recordset.extend(new_rrsets["rrsets"])
        new_rrset_types = [(item["name"], item["type"]) for item in new_rrsets["rrsets"]]
        upstream_rrset_types = [(item["name"], item["type"]) for item in upstream_zone["rrsets"]]
        for rrset_type in upstream_rrset_types:
            if rrset_type not in new_rrset_types:
                ctx.obj.logger.debug(f"Marking {rrset_type} for deletion.")
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
        ctx.obj.logger.debug(f"Final recordset prepared: {new_rrsets['rrsets']}.")
    r = utils.http_patch(uri, ctx, payload=new_rrsets)
    if r.status_code == 204:
        ctx.obj.logger.info("RRset imported successfully.")
        utils.exit_action(ctx, True, "RRset imported.", r)
    else:
        ctx.obj.logger.error(f"Failed to import RRset. Status code: {r.status_code}.")
        utils.exit_action(ctx, False, "Failed to import RRset.", r)


@record.command("spec")
def record_spec():
    """Open the record specification on https://redocly.github.io."""
    utils.open_spec("record")


def check_records_for_identical_content(
    ctx: click.Context,
    new_rrsets: dict[str, Any],
    upstream_zone: dict[str, Any],
    replace: bool,
) -> NoReturn | None:
    """
    Check if the new RRsets are already present in the upstream zone.
    This function compares the contents of new RRsets with those in the upstream zone,
    ignoring the 'modified_at' field. If all RRsets are already present, it logs a message
    and exits with success status.
    Args:
        ctx: Click context object.
        new_rrsets: A dictionary containing the new RRsets to check.
                    Expected to have a 'rrsets' key with a list of RRset dictionaries.
        upstream_zone: A dictionary containing the upstream zone RRsets.
                       Expected to have a 'rrsets' key with a list of RRset dictionaries.
        replace: If True, checks for exact match in both content and count.
                 If False, only checks if all new RRsets are present in the upstream zone.
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

    ctx.obj.logger.info("Checking if requested RRsets are already present in the upstream zone.")
    # Normalize both sets of RRsets
    new_rrset_contents = [
        _normalize_rrset(item) for item in new_rrsets["rrsets"] if item["type"] != "SOA"
    ]
    ctx.obj.logger.debug(f"Normalized new rrsets: {new_rrset_contents}.")
    upstream_rrset_contents = [
        _normalize_rrset(item) for item in upstream_zone["rrsets"] if item["type"] != "SOA"
    ]
    ctx.obj.logger.debug(f"Normalized upstream rrsets: {upstream_rrset_contents}.")
    # Check for presence of all new RRsets in upstream
    if not replace and all(rrset in upstream_rrset_contents for rrset in new_rrset_contents):
        ctx.obj.logger.info("Requested RRsets are already present in the upstream zone.")
        utils.exit_action(ctx, success=True, message="Requested RRsets are already present.")
    # Check for exact match if replace is True
    if replace and (
        all(rrset in upstream_rrset_contents for rrset in new_rrset_contents)
        and len(upstream_rrset_contents) == len(new_rrset_contents)
    ):
        ctx.obj.logger.info("Requested RRsets are already present in the upstream zone.")
        utils.exit_action(ctx, success=True, message="Requested RRsets are already present.")


def validate_rrset_import(ctx: click.Context, rrset: dict[str, Any]) -> None:
    """
    Validates the structure and content of an RRset dictionary for import.
    Args:
        ctx: Click context object.
        rrset: A dictionary representing the RRset to validate.
               Expected to contain 'rrsets' and either 'id' or 'name'.
    """
    ctx.obj.logger.info("Validating RRset import structure and content.")
    if not isinstance(rrset, dict):
        ctx.obj.logger.error("RRset must be supplied as a single dictionary.")
        utils.exit_action(
            ctx, success=False, message="You must supply rrsets as a single dictionary."
        )
    if not rrset.get("rrsets"):
        ctx.obj.logger.error("The key 'rrsets' must be present in the RRset dictionary.")
        utils.exit_action(ctx, success=False, message="The key 'rrsets' must be present.")
    utils.is_id_or_name_present(ctx, rrset)
    if rrset.get("name") and not rrset.get("id"):
        rrset["id"] = rrset["name"]
    for key in list(rrset.keys()):
        if key not in ("id", "rrsets"):
            del rrset[key]
    ctx.obj.logger.debug("RRset validation successful.")


def merge_rrsets(uri: str, ctx: click.Context, new_rrset: dict) -> list[dict]:
    """
    Merge the upstream and local rrset records to create a unified and deduplicated set.
    Args:
        uri: The URI for the zone.
        ctx: Click context object.
        new_rrset: The new RRSet to merge.
    Returns:
        Merged and deduplicated list of RRSet records.
    """
    ctx.obj.logger.info(f"Merging RRSet for {new_rrset['name']} ({new_rrset['type']}).")
    zone_rrsets = query_zone_rrsets(uri, ctx)
    merged_rrsets = new_rrset["records"].copy()
    for upstream_rrset in zone_rrsets:
        if all(upstream_rrset[key] == new_rrset[key] for key in ("name", "type")):
            merged_rrsets.extend(
                record_item
                for record_item in upstream_rrset["records"]
                if record_item["content"] != new_rrset["records"][0]["content"]
            )
    ctx.obj.logger.debug(f"Merged RRSet: {merged_rrsets}.")
    return merged_rrsets


def is_matching_rrset_present(uri: str, ctx: click.Context, new_rrset: dict) -> dict:
    """
    Checks if an RRSet is already present in the DNS database.
    Only checks for name and type, not individual records.
    Args:
        uri: The URI for the zone.
        ctx: Click context object.
        new_rrset: The RRSet to check.
    Returns:
        The matching RRSet if found, otherwise an empty dict.
    """
    ctx.obj.logger.info(f"Checking for existing RRSet: {new_rrset['name']} ({new_rrset['type']}).")
    zone_rrsets = query_zone_rrsets(uri, ctx)
    for upstream_rrset in zone_rrsets:
        if all(upstream_rrset[key] == new_rrset[key] for key in ("name", "type")):
            ctx.obj.logger.debug("Matching RRSet found.")
            return upstream_rrset
    ctx.obj.logger.debug("No matching RRSet found.")
    return {}


def query_zone_rrsets(uri: str, ctx: click.Context) -> list[dict]:
    """
    Queries the configuration of the given zone and returns a list of all RRSets.
    Args:
        uri: The URI to query for the zone's RRSets.
        ctx: Click context object.
    Returns:
        A list of RRSet dictionaries.
    Exits:
        Calls utils.exit_action with success=False if the request fails.
    """
    ctx.obj.logger.info(f"Querying RRSets for zone at {uri}.")
    r = utils.http_get(uri, ctx)
    if r.status_code != 200:
        ctx.obj.logger.error(f"Failed to query RRSets: {r.text}.")
        utils.exit_action(ctx, False, "Failed to query RRSets.", response=r)
    ctx.obj.logger.debug("Successfully queried RRSets.")
    return r.json()["rrsets"]


def is_value_present(uri: str, ctx: click.Context, new_rrset: dict) -> bool:
    """
    Checks if a matching RRSet is present and if the new record is already present.
    Args:
        uri: The URI for the zone.
        ctx: Click context object.
        new_rrset: The RRSet to check.
    Returns:
        True if both the RRSet and all records are present, otherwise False.
    """
    ctx.obj.logger.info(
        f"Checking if value is present for RRSet: {new_rrset['name']} ({new_rrset['type']})."
    )
    zone_rrsets = query_zone_rrsets(uri, ctx)
    # remove modified_at to enable idempotence
    zone_rrsets = [
        {
            **entry,
            "records": [
                {k: v for k, v in record_entry.items() if k != "modified_at"}
                for record_entry in entry["records"]
            ],
        }
        for entry in zone_rrsets
    ]
    for rrset in zone_rrsets:
        if all(rrset[key] == new_rrset[key] for key in ("name", "type", "ttl")) and all(
            record_item in rrset["records"] for record_item in new_rrset["records"]
        ):
            ctx.obj.logger.debug("Matching RRSet and records found.")
            return True
    ctx.obj.logger.debug("Matching RRSet or records not found.")
    return False
