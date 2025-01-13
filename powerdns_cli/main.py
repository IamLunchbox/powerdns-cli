#!/usr/bin/env python3
"""
powerdns-cli: Manage PowerDNS Zones/Records
"""

import json
import sys

import click
import requests


# create click command group with 4 global options
@click.group()
@click.option(
    "-k",
    "--apikey",
    help="Provide your apikey manually, if not through environment variable",
    type=click.STRING,
    default=None,
)
@click.option(
    "-u",
    "--url",
    help="DNS servers api url",
    type=click.STRING,
)
@click.option(
    "-f",
    "--force",
    help="Force execution and skip confirmations",
    is_flag=True,
    default=False,
    show_default=True,
)
@click.option(
    "-j",
    "--json-output",
    help="Print json output",
    is_flag=True,
    show_default=True,
    default=False,
)
@click.pass_context
def cli(ctx, apikey, url, force, json_output):
    """Main Entrypoint to powerdns-cli function.
    Checks apikey through  __setup_api_key__
    and lets the given function do the rest"""
    ctx.ensure_object(dict)
    ctx.obj["apihost"] = url
    ctx.obj["key"] = apikey
    ctx.obj["force"] = force
    ctx.obj["json"] = json_output
    __setup_api_key__(ctx)


# Add record
@cli.command()
@click.argument("name", type=click.STRING)
@click.argument("zone", type=click.STRING)
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
    ),
)
@click.argument("content", type=click.STRING)
@click.option(
    "-d",
    "--disabled",
    help="Disable the record",
    is_flag=True,
    default=False,
)
@click.option("--ttl", default=3600, type=click.INT, help="Set default time to live")
@click.pass_context
def add_record(
    ctx,
    name,
    record_type,
    content,
    zone,
    disabled,
    ttl,
):
    """
    Adds a new DNS record of different types. Use @ if you want to enter a
    record for the top level.

    A record:
    powerdns-cli add_single_record test01 exmaple.org A 10.0.0.1
    MX record:
    powerdns-cli add_single_record mail example.org MX "10 10.0.0.1"
    CNAME record:
    powerdns-cli add_single_record test02 example.org CNAME test01.example.org
    """
    if not zone.endswith("."):
        zone += "."
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{zone}"

    # Define FQDN
    if name == "@":
        dns_record = f"{zone}"
    else:
        dns_record = f"{name}.{zone}"
    record = {
        "name": dns_record,
        "type": record_type,
        "ttl": ttl,
        "changetype": "REPLACE",
        "records": [{"content": content, "disabled": disabled}],
    }
    if not check_for_record(uri, record, ctx):
        payload = {
            "rrsets": [
                record,
            ]
        }

        r = requests.patch(uri, json=payload, headers=ctx.obj["auth_header"])

        if r.status_code in (200, 204):
            print_output(
                {
                    "message": f"Added {payload}",
                    "statuscode": r.status_code,
                    "content": r.text,
                },
                ctx,
            )
            sys.exit(0)

        else:
            print_output(
                {
                    "status": "error",
                    "message": f"Adding {payload} failed",
                    "statuscode": r.status_code,
                    "content": r.text,
                },
                ctx,
            )
            sys.exit(1)
    else:
        print("The record is already present.")


# Extend record
@cli.command()
@click.argument("name", type=click.STRING)
@click.argument("zone", type=click.STRING)
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
    ),
)
@click.argument("content", type=click.STRING, nargs=-1)
@click.option(
    "-d",
    "--disabled",
    help="Disable the record",
    is_flag=True,
    default=False,
)
@click.option("--ttl", default=3600, type=click.INT, help="Set time to live")
@click.pass_context
def edit_record(
    ctx,
    name,
    record_type,
    content,
    zone,
    disabled,
    ttl,
):
    """
    Add new DNS records
    Create new DNS records of different types. Use @ if you want to enter a
    record for the top level.

    A record:
    powerdns-cli add_records test01 exmaple.org A 10.0.0.1
    MX record:
    powerdns-cli add_records mail example.org MX "10 10.0.0.1"
    CNAME record:
    powerdns-cli add_records test02 exmaple.org CNAME test01.example.org
    """
    if not zone.endswith("."):
        zone += "."
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{zone}"

    # Define FQDN
    if name == "@":
        dns_record = f"{zone}"
    else:
        dns_record = f"{name}.{zone}"
    record = {
        "name": dns_record,
        "type": record_type,
        "ttl": ttl,
        "changetype": "REPLACE",
        "records": [],
    }
    for item in content:
        record["records"].append({"content": item, "disabled": disabled})
    if not check_for_record(uri, record, ctx):
        payload = {"rrsets": [record]}

        r = requests.patch(uri, json=payload, headers=ctx.obj["auth_header"])

        if r.status_code in (200, 204):
            print_output(
                {
                    "status": "success",
                    "message": f"Added {payload}",
                    "statuscode": r.status_code,
                    "content": r.text,
                },
                ctx,
            )
            sys.exit(0)

        else:
            print_output(
                {
                    "status": "error",
                    "message": f"Adding {payload} failed",
                    "statuscode": r.status_code,
                    "content": r.text,
                },
                ctx,
            )
            sys.exit(1)
    else:
        print("The record is already present.")


# Reduce record
@cli.command()
@click.argument("name", type=click.STRING)
@click.argument("zone", type=click.STRING)
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
    ),
)
@click.argument("content", type=click.STRING, nargs=-1)
@click.option("--ttl", default=3600, type=click.INT, help="Set time to live")
@click.pass_context
def edit_record(
    ctx,
    name,
    record_type,
    content,
    zone,
    disabled,
    ttl,
):
    """
    Add new DNS records
    Create new DNS records of different types. Use @ if you want to enter a
    record for the top level.

    A record:
    powerdns-cli add_records test01 exmaple.org A 10.0.0.1
    MX record:
    powerdns-cli add_records mail example.org MX "10 10.0.0.1"
    CNAME record:
    powerdns-cli add_records test02 exmaple.org CNAME test01.example.org
    """
    if not zone.endswith("."):
        zone += "."
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{zone}"

    # Define FQDN
    if name == "@":
        dns_record = f"{zone}"
    else:
        dns_record = f"{name}.{zone}"
    record = {
        "name": dns_record,
        "type": record_type,
        "ttl": ttl,
        "changetype": "REPLACE",
        "records": [],
    }
    for item in content:
        record["records"].append({"content": item, "disabled": disabled})
    if not check_for_record(uri, record, ctx):
        payload = {"rrsets": [record]}

        r = requests.patch(uri, json=payload, headers=ctx.obj["auth_header"])

        if r.status_code in (200, 204):
            print_output(
                {
                    "status": "success",
                    "message": f"Added {payload}",
                    "statuscode": r.status_code,
                    "content": r.text,
                },
                ctx,
            )
            sys.exit(0)

        else:
            print_output(
                {
                    "status": "error",
                    "message": f"Adding {payload} failed",
                    "statuscode": r.status_code,
                    "content": r.text,
                },
                ctx,
            )
            sys.exit(1)
    else:
        print("The record is already present.")


@cli.command()
@click.argument("name", type=click.STRING)
@click.argument("zone")
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
@click.pass_context
def delete_record(ctx, name, record_type, zone, content):
    """
    Delete DNS records of different types. Must match the record type
    exactly, otherwise powerdns will fail.
    Example:
    powerdns-cli delete_records mail exmaple.org A 10.0.0.1
    """
    if not zone.endswith("."):
        zone += "."
    dns_record = f"{name}.{zone}"
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{zone}"

    # Get entries in the zone
    r = requests.get(uri, headers=ctx.obj["auth_header"])
    existing_record = None
    if r.status_code == 200:
        for record in r.json()["rrsets"]:
            if record["name"] == dns_record and record["type"] == record_type:
                for entry in record["records"]:
                    if entry["content"] == content:
                        existing_record = record
    else:
        print_output(
            {
                "status": "error",
                "message": f"Could not query for {dns_record}",
                "statuscode": r.status_code,
                "content": r.text,
            },
            ctx,
        )
        sys.exit(1)
    if not existing_record:
        print_output(
            {
                "status": "success",
                "message": f"{dns_record} does not exist",
                "statuscode": r.status_code,
                "content": r.text,
            },
            ctx,
        )
        sys.exit(0)
    confirm(
        f"!!!! WARNING !!!!!\nYou are attempting to delete {content} "
        f"from {existing_record}\nAre you sure? [Y/N] ",
        ctx,
    )
    payload = {
        "rrsets": [
            {
                "name": dns_record,
                "type": record_type,
                "changetype": "DELETE",
                "records": [
                    {
                        "content": content,
                    }
                ],
            }
        ]
    }

    r = requests.patch(uri, data=json.dumps(payload), headers=ctx.obj["auth_header"])

    if r.status_code not in (200, 204):
        print_output(
            {
                "status": "error",
                "message": f"Deleting rrset {payload} failed",
                "content": r.text,
                "statuscode": r.status_code,
            },
            ctx,
        )
        sys.exit(1)

    else:
        print_output(
            {
                "status": "success",
                "message": f"Deleting rrset {payload} succeeded",
                "content": r.text,
                "statuscode": r.status_code,
            },
            ctx,
        )
        sys.exit(0)


@cli.command()
@click.argument("zone", type=click.STRING)
@click.argument("nameserver", type=click.STRING)
# TODO
@click.argument(
    "master",
    type=click.Choice(["10.10.100.53"]),
    metavar="ZONE-MASTER",
)
@click.argument(
    "zonetype",
    type=click.Choice(["MASTER", "NATIVE", "SLAVE"], case_sensitive=False),
)
@click.option("--ttl", default=3600, type=click.INT, help="Set default priority")
@click.pass_context
def add_zone(ctx, zone, nameserver, master, zonetype, ttl):
    """
    Add new DNS zone

    Create Master, Native or Slave zone
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones"
    masters = []
    nameservers = []
    if not zone.endswith("."):
        zone += "."
    if master:
        for master in master.split(","):
            masters.append(master)
    if nameserver:
        for server in nameserver.split(","):
            if not server.endswith("."):
                server += "."
            nameservers.append(server)
    zonetype.capitalize()
    if zonetype == "MASTER":
        payload = {
            "name": zone,
            "kind": zonetype,
            "masters": [],
            "nameservers": nameservers,
        }
    elif zonetype == "NATIVE":
        click.echo("Native entries are not supported right now")
        sys.exit(1)
        # payload = {
        #     "name": zone,
        #     "kind": zonetype,
        #     "masters": [],
        #     "nameservers": nameservers,
        # }
    else:
        click.echo("Slave entries are not supported right now")
        sys.exit(1)
        # payload = {
        #     "name": zone,
        #     "kind": zonetype,
        #     "masters": masters,
        #     "nameservers": [],
        # }
    zone_exist_check = requests.get(
        f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{zone}",
        headers=ctx.obj["auth_header"],
    )
    if zone_exist_check.status_code == 200:
        print_output(
            {
                "status": "error",
                "message": f"DNS zone {zone} already exist.",
                "statuscode": zone_exist_check.status_code,
                "content": zone_exist_check.text,
            },
            ctx,
        )
        sys.exit(1)
    r = requests.post(uri, json=payload, headers=ctx.obj["auth_header"])
    if r.status_code not in (200, 201, 204):
        print_output(
            {
                "status": "error",
                "message": f"DNS zone {zone} could not be added",
                "statuscode": r.status_code,
                "content": r.text,
            },
            ctx,
        ),
        sys.exit(1)
    payload = {
        "rrsets": [
            {
                "name": zone,
                "type": "SOA",
                "ttl": ttl,
                "changetype": "REPLACE",
                "records": [
                    # todo
                    {
                        "content": ". . 0 10800 3600 604800 3600",
                        "disabled": False,
                    }
                ],
            }
        ]
    }
    r = requests.patch(uri + "/" + zone, json=payload, headers=ctx.obj["auth_header"])
    if r.status_code in (200, 204):
        print_output(
            {
                "status": "success",
                "message": f"{zone} is set up",
                "content": r.text,
                "statuscode": r.status_code,
            },
            ctx,
        )
        sys.exit(0)
    else:
        print_output(
            {
                "status": "error",
                "message": f"Error fixing the SOA Record",
                "statuscode": r.status_code,
                "content": r.text,
            },
            ctx,
        )
        sys.exit(1)


@cli.command()
@click.argument("zone", type=click.STRING)
@click.pass_context
def list_zone(ctx, zone):
    pass


@cli.command()
@click.argument("zone", type=click.STRING)
@click.pass_context
def delete_zone(ctx, zone):
    """
    Delete DNS Zones
    """
    if not zone.endswith("."):
        zone += "."
    uri = f"{ctx.obj['apihost']}/api/v1/servers/" f"localhost/zones/{zone}"

    confirm(
        f"!!!! WARNING !!!!!\n"
        f"You are attempting to delete {zone}\n"
        f"Are you sure? [Y/N] ",
        ctx,
    )
    r = requests.delete(
        uri,
        headers=ctx.obj["auth_header"],
    )
    if r.status_code not in (200, 204):
        print_output(
            {
                "status": "error",
                "message": f"Deleting {zone} failed. " f"Status was: {r.status_code}",
                "content": r.text,
                "statuscode": r.status_code,
            },
            ctx,
        )
        sys.exit(1)
    print_output(
        {
            "status": "success",
            "message": f"Deleted {zone}",
            "content": r.text,
            "statuscode": r.status_code,
        },
        ctx,
    )
    sys.exit(0)


@cli.command()
@click.pass_context
def query_config(ctx):
    """
    Query PDNS Config
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/config"
    r = requests.get(uri, headers=ctx.obj["auth_header"])
    if r.status_code == 200:
        print_output(
            {
                "status": "success",
                "message": r.text,
                "content": r.text,
                "statuscode": r.status_code,
            },
            ctx,
        )
        sys.exit(0)
    else:
        print_output(
            {
                "status": "error",
                "message": "Querying config failed",
                "content": r.text,
                "statuscode": r.status_code,
            },
            ctx,
        )
        sys.exit(1)


@cli.command()
@click.pass_context
def query_stats(ctx):
    """
    Query DNS Stats
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/statistics"
    r = requests.get(uri, headers=ctx.obj["auth_header"])
    if r.status_code == 200:
        print_output(
            {
                "status": "success",
                "message": r.text,
                "content": r.text,
                "statuscode": r.status_code,
            },
            ctx,
        )
        sys.exit(0)
    else:
        print_output(
            {
                "status": "error",
                "message": f"Querying stats failed",
                "statuscode": r.status_code,
                "content": r.text,
            },
            ctx,
        )
        sys.exit(1)


@cli.command()
@click.argument(
    "zone",
    type=click.STRING,
)
@click.pass_context
def query_zone(ctx, zone):
    """
    Query DNS Zones

    Query existing DNS Zones
    """
    if zone is None:
        uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones"
    else:
        if not zone.endswith("."):
            zone += "."
        uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{zone}"
    r = requests.get(uri, headers=ctx.obj["auth_header"])
    if r.status_code == 200:
        print_output(
            {
                "status": "success",
                "message": r.text,
                "content": r.text,
                "statuscode": r.status_code,
            },
            ctx,
        )
        sys.exit(0)
    else:
        print_output(
            {
                "status": "error",
                "message": f"An unknown error occurred.",
                "content": r.text,
                "statuscode": r.status_code,
            },
            ctx,
        )
        sys.exit(1)


@cli.command()
@click.pass_context
def get_zones(ctx):
    """
    Get all zones of dns server
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones"
    r = requests.get(uri, headers=ctx.obj["auth_header"])
    if r.status_code == 200:
        print_output(
            {
                "status": "success",
                "message": r.text,
                "content": r.text,
                "statuscode": r.status_code,
            },
            ctx,
        )
        sys.exit(0)
    else:
        print_output(
            {
                "status": "error",
                "message": f"An unknown error occurred",
                "content": r.text,
                "statuscode": r.status_code,
            },
            ctx,
        )
        sys.exit(1)


@cli.command()
@click.pass_context
def import_file(ctx):
    pass


@cli.command()
@click.argument("search-string")
@click.option("--count", help="Number of items to output", default=5, type=click.INT)
@click.pass_context
def search(ctx, search_string, count):
    """Do fulltext search in dns database"""
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/search-data"
    r = requests.get(
        uri,
        headers=ctx.obj["auth_header"],
        params={"q": f"*{search_string}*", "max": count},
    )
    if r.status_code == 200:
        print_output(
            {
                "status": "success",
                "message": r.text,
                "content": r.text,
                "statuscode": r.status_code,
            },
            ctx,
        )
        sys.exit(0)
    else:
        print_output(
            {
                "status": "error",
                "message": f"Export failed",
                "content": r.text,
                "statuscode": r.status_code,
            },
            ctx,
        )
        sys.exit(1)


@cli.command()
@click.argument("zone")
@click.pass_context
def export(ctx, zone):
    """Export zone in BIND format"""
    if not zone.endswith("."):
        zone += "."
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{zone}/export"
    r = requests.get(
        uri,
        headers=ctx.obj["auth_header"],
    )
    if r.status_code == 200:
        print_output(
            {
                "status": "success",
                "message": r.text,
                "content": r.text,
                "statuscode": r.status_code,
            },
            ctx,
        )
    else:
        print_output(
            {
                "status": "error",
                "message": f"Export failed",
                "content": r.text,
                "statuscode": r.status_code,
            },
            ctx,
        )
        sys.exit(1)


def __setup_api_key__(ctx):
    """Checks for a given api key and fails otherwise"""
    true_key = False
    if ctx.obj["key"]:
        true_key = ctx.obj["key"]
    if not true_key:
        print("No API-KEY given. Set key through environment or through flags")
        sys.exit(1)
    ctx.obj["auth_header"] = {"X-API-Key": true_key}


def print_output(content: dict, ctx):
    """Helper function to print a message in the appropriate format.
    Is needed since the powerdns api outputs different content types, not
    json all the time.
    It tries to determine the content type and then output it in the appropriate
    format, depending on user preference."""
    # this is an example message
    # {
    #     "status": "success",
    #     "message": f"Added {payload}",
    #     "statuscode": r.status_code,
    #     "content": r.text,
    # }, ctx
    print_raw = False
    # check if caller of this function passed valid json as message output.
    # If yes, this should be output as json
    try:
        content.update({"message": json.loads(content.get("message"))})
    except json.JSONDecodeError:
        print_raw = True
    # check if raw http response body is json and convert it into a dict
    try:
        content.update({"content": json.loads(content.get("content"))})
    except json.JSONDecodeError:
        pass
    # print all output if something went wrong
    if content.get("status") == "error":
        click.echo(json.dumps(content, indent=2))
    # print all output if json flag is set, users can filter it
    elif ctx.obj["json"]:
        click.echo(json.dumps(content, indent=2))
    else:
        if not content.get("message"):
            # print pretty message if message is empty
            click.echo(
                json.dumps(
                    {f"message": f"No message. Status: {content.get('statuscode')}"}
                )
            )
        elif print_raw:
            # print plain text if text was no json
            click.echo(content.get("message"))
        else:
            # print the message as plain json
            click.echo(json.dumps(content.get("message")))


def check_for_record(uri: str, new_record: dict, ctx) -> bool:
    """Helper function to check if rrset is already existing."""
    r = requests.get(uri, headers=ctx.obj["auth_header"])
    if r.status_code == 200:
        rrset = r.json()["rrsets"]
    else:
        raise RuntimeError(
            f"The zone exists, but no zone information could be obtained. "
            f"The statuscode was {r.status_code}"
        )

    # response from api
    # "rrsets": [
    #     {
    #         "comments": [],
    #         "name": "test.example.org.",
    #         "records": [
    #             {
    #                 "content": "192.168.0.5",
    #                 "disabled": false
    #             }
    #         ],
    #         "ttl": 3600,
    #         "type": "A"
    #     },
    # ]

    # passed as rrset
    # {       'name': dns_record,
    #         'type': record_type,
    #         'ttl': ttl,
    #         'changetype': 'REPLACE',
    #         'records': [{
    #             'content': content,
    #             'disabled': disabled,
    #         }],
    # }
    check_duplicate(rrset, new_record)
    return False


def check_duplicate(upstream_rrset: list, new_rrset: dict):
    for rrset in upstream_rrset:
        # go through all the records to find matching rrset
        if (all(rrset[key] == new_rrset[key] for key in ("name", "type", "ttl"))
                and all(entry in rrset["records"] for entry in new_rrset["records"])
        ):
            print("Record is already there")
            sys.exit(0)


def confirm(message, ctx):
    """Helper function to keep users from doing potentially dangerous actions.
    Uses the force flag to determine if a manual confirmation is required."""
    if not ctx.obj["force"]:
        click.echo(message)
        confirmation = input()
        if confirmation not in ("y", "Y", "YES", "yes", "Yes"):
            click.echo("Aborting")
            sys.exit(1)


if __name__ == "__main__":
    cli(auto_envvar_prefix="POWERDNS_CLI")
