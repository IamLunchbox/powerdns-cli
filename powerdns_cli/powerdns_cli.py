#!/usr/bin/env python3
"""
powerdns-cli: Manage PowerDNS Zones/Records
"""
import json
import re
import ipaddress

import click
import requests

from . import utils


class ZoneType(click.ParamType):
    """Conversion class to ensure, that a provided string is a valid dns name"""

    name = "zone"

    def convert(self, value, param, ctx) -> str:
        if ctx is None:  # Graciously assume that users run the latest powerdns-version
            try:
                if not re.match(
                    r"^((?!-)[-A-Z\d]{1,63}(?<!-)[.])+(?!-)[-A-Z\d]{1,63}(?<!-)(\.|\.\.[\w_]+)?$",
                    value,
                    re.IGNORECASE,
                ):
                    raise click.BadParameter("You did not provide a valid zone name.")
            except (AttributeError, TypeError):
                self.fail(f"{value!r} couldn't be converted to a canonical zone", param, ctx)
        else:
            try:
                if ctx.obj.get("major_version", 4) >= 5 and not re.match(
                    r"^((?!-)[-A-Z\d]{1,63}(?<!-)[.])+(?!-)[-A-Z\d]{1,63}(?<!-)(\.|\.\.[\w_]+)?$",
                    value,
                    re.IGNORECASE,
                ):
                    raise click.BadParameter("You did not provide a valid zone name.")
                if ctx.obj.get("major_version", 4) <= 4 and not re.match(
                    r"^((?!-)[-A-Z\d]{1,63}(?<!-)[.])+(?!-)[-A-Z\d]{1,63}(?<!-)[.]?$",
                    value,
                    re.IGNORECASE,
                ):
                    raise click.BadParameter("You did not provide a valid zone name.")
            except (AttributeError, TypeError):
                self.fail(f"{value!r} couldn't be converted to a canonical zone", param, ctx)

        if not value.endswith(".") and ".." not in value:
            value += "."
        return value


Zone = ZoneType()


class IPRangeType(click.ParamType):
    """Conversion class to ensure, that a provided string is a valid ip range"""

    name = "iprange"

    def convert(self, value, param, ctx) -> str:
        try:
            ipaddress.ip_network(value, strict=False)
            return value
        except (ValueError, ipaddress.AddressValueError):
            self.fail(f"{value!r} is no valid IP-address range", param, ctx)


IPRange = IPRangeType()


# create click command group with 3 global options
@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "-a",
    "--apikey",
    help="Provide your apikey manually",
    type=click.STRING,
    default=None,
    required=True,
)
@click.option("-u", "--url", help="DNS servers api url", type=click.STRING, required=True)
@click.option(
    "-k",
    "--insecure",
    help="Ignore invalid certificates",
    is_flag=True,
    default=False,
    show_default=True,
)
@click.option(
    "--skip-check",
    help="Skips the preflight request towards your apihost",
    is_flag=True,
    default=False,
)
@click.pass_context
def cli(ctx, apikey, url, insecure, skip_check):
    """Manage PowerDNS Authoritative Nameservers and their Zones/Records

    Your target server api must be specified through the corresponding cli-flags.
    You can also export them with the prefix POWERDNS_CLI_, for example:
    export POWERDNS_CLI_APIKEY=foobar
    """
    ctx.ensure_object(dict)
    ctx.obj["apihost"] = url
    ctx.obj["key"] = apikey

    session = requests.session()
    session.verify = insecure
    session.headers = {"X-API-Key": ctx.obj["key"]}
    ctx.obj["session"] = session
    if not skip_check:
        uri = f"{ctx.obj['apihost']}/api/v1/servers"
        preflight_request = utils.http_get(uri, ctx)
        if not preflight_request.status_code == 200:
            click.echo(
                json.dumps(
                    {
                        "message": "Error, did not successfully connect to sever, "
                        f"status {preflight_request.status_code}. "
                        "Are your credentials correct?"
                    }
                )
            )
            raise SystemExit(1)
        ctx.obj["major_version"] = int(
            [
                server["version"]
                for server in preflight_request.json()
                if server["id"] == "localhost"
            ][0].split(".")[0]
        )
    else:
        ctx.obj["major_version"] = 4


@cli.group()
def autoprimary():
    """Set up autoprimary configuration"""


@autoprimary.command("add")
@click.argument("ip", type=click.STRING)
@click.argument("nameserver", type=click.STRING)
@click.option("-a", "--account", default="", type=click.STRING, help="Option")
@click.pass_context
def autoprimary_add(
    ctx,
    ip,
    nameserver,
    account,
):
    """
    Adds an autoprimary upstream dns server
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/autoprimaries"
    payload = {"cidr": ip, "nameserver": nameserver, "account": account}
    if utils.is_autoprimary_present(uri, ctx, ip, nameserver):
        click.echo(
            json.dumps(
                {"message": f"Autoprimary {ip} with nameserver {nameserver} already present"}
            )
        )
        raise SystemExit(0)
    r = utils.http_post(uri, ctx, payload)
    if utils.create_output(
        r,
        (201,),
        optional_json={"message": f"Autoprimary {ip} with nameserver {nameserver} added"},
    ):
        raise SystemExit(0)
    raise SystemExit(1)


@autoprimary.command("delete")
@click.argument("ip", type=click.STRING)
@click.argument("nameserver", type=click.STRING)
@click.pass_context
def autoprimary_delete(ctx, ip, nameserver):
    """
    Deletes an autoprimary from the dns server configuration
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/autoprimaries"
    if utils.is_autoprimary_present(uri, ctx, ip, nameserver):
        uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/autoprimaries/{ip}/{nameserver}"
        r = utils.http_delete(uri, ctx)
        if utils.create_output(
            r,
            (204,),
            optional_json={"message": f"Autoprimary {ip} with nameserver {nameserver} deleted"},
        ):
            raise SystemExit(0)
    else:
        click.echo(
            json.dumps({"message": f"Autoprimary {ip} with nameserver {nameserver} already absent"})
        )
        raise SystemExit(0)


@autoprimary.command("list")
@click.pass_context
def autoprimary_list(ctx):
    """
    Lists all currently configured autoprimary servers
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/autoprimaries"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@cli.group()
def config():
    """Overall server configuration"""


@config.command("export")
@click.pass_context
def config_export(ctx):
    """
    Query the configuration of this PowerDNS instance
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/config"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@config.command("list")
@click.pass_context
def config_list(ctx):
    """
    Lists configured dns-servers
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@config.command("stats")
@click.pass_context
def config_stats(ctx):
    """
    Displays operational statistics of your dns server
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/statistics"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@cli.group()
def cryptokey():
    """Configure cryptokeys"""


@cryptokey.command("add")
@click.argument("dns_zone", type=Zone, metavar="zone")
@click.argument("key-type", type=click.Choice(["ksk", "zsk"]))
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
def cryptokey_add(ctx, dns_zone, key_type, active, publish, bits, algorithm):
    """
    Adds a cryptokey to the zone. Is disabled and not published by default
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys"
    payload = {"active": active, "published": publish, "keytype": key_type}
    # Click CLI escapes newline characters
    for key, val in {"bits": bits, "algorithm": algorithm}.items():
        if val:
            payload[key] = val
    r = utils.http_post(uri, ctx, payload)
    if utils.create_output(
        r,
        (201,),
    ):
        raise SystemExit(0)
    raise SystemExit(1)


@cryptokey.command("delete")
@click.pass_context
@click.argument("dns_zone", type=Zone, metavar="zone")
@click.argument("cryptokey-id", type=click.INT)
def cryptokey_delete(ctx, dns_zone, cryptokey_id):
    """
    Deletes the given cryptokey-id from all the configured cryptokeys
    """
    uri = (
        f"{ctx.obj['apihost']}"
        f"/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys/{cryptokey_id}"
    )
    utils.does_cryptokey_exist(uri, f"Cryptokey with id {cryptokey_id} already absent", 0, ctx)
    r = utils.http_delete(uri, ctx)
    if utils.create_output(
        r,
        (204,),
        optional_json={"message": f"Deleted id {cryptokey_id} for {dns_zone}"},
    ):
        raise SystemExit(0)
    raise SystemExit(1)


@cryptokey.command("disable")
@click.pass_context
@click.argument("dns_zone", type=Zone, metavar="zone")
@click.argument("cryptokey-id", type=click.INT)
def cryptokey_disable(ctx, dns_zone, cryptokey_id):
    """
    Disables the cryptokey for this zone.
    """
    uri = (
        f"{ctx.obj['apihost']}"
        f"/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys/{cryptokey_id}"
    )
    payload = {
        "id": cryptokey_id,
        "active": False,
    }
    r = utils.does_cryptokey_exist(uri, f"Cryptokey with id {cryptokey_id} does not exist", 1, ctx)
    if not r.json()["active"]:
        click.echo(json.dumps({"message": f"Cryptokey with id {cryptokey_id} is already inactive"}))
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
@click.argument("dns_zone", type=Zone, metavar="zone")
@click.argument("cryptokey-id", type=click.INT)
def cryptokey_enable(ctx, dns_zone, cryptokey_id):
    """
    Enables an already existing cryptokey
    """
    uri = (
        f"{ctx.obj['apihost']}"
        f"/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys/{cryptokey_id}"
    )
    payload = {
        "id": cryptokey_id,
        "active": True,
    }
    r = utils.does_cryptokey_exist(uri, f"Cryptokey with id {cryptokey_id} does not exist", 1, ctx)
    if r.json()["active"]:
        click.echo(json.dumps({"message": f"Cryptokey with id {cryptokey_id} is already active"}))
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
@click.argument("dns_zone", type=Zone, metavar="zone")
@click.argument("cryptokey-id", type=click.STRING)
def cryptokey_export(ctx, dns_zone, cryptokey_id):
    """
    Exports the cryptokey with the given id including the private key
    """
    uri = (
        f"{ctx.obj['apihost']}"
        f"/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys/{cryptokey_id}"
    )
    utils.does_cryptokey_exist(uri, f"Cryptokey with id {cryptokey_id} does not exist", 1, ctx)
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@cryptokey.command("import")
@click.argument("dns_zone", type=Zone, metavar="zone")
@click.argument("key-type", type=click.Choice(["ksk", "zsk"]))
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
    Adds a cryptokey to the zone. Is disabled and not published by default
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys"
    # Click CLI escapes newline characters
    secret = private_key.replace("\\n", "\n")
    payload = {
        "active": active,
        "published": publish,
        "privatekey": secret,
        "keytype": key_type,
    }
    if utils.is_dnssec_key_present(uri, secret, ctx):
        click.echo(
            json.dumps({"message": "The provided dnssec-key is already present at the backend"})
        )
        raise SystemExit(0)
    r = utils.http_post(uri, ctx, payload)
    if utils.create_output(
        r,
        (201,),
    ):
        raise SystemExit(0)
    raise SystemExit(1)


@cryptokey.command("list")
@click.pass_context
@click.argument("dns_zone", type=Zone, metavar="zone")
def cryptokey_list(ctx, dns_zone):
    """
    Lists all currently configured cryptokeys for this zone without displaying secrets
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@cryptokey.command("publish")
@click.pass_context
@click.argument("dns_zone", type=Zone, metavar="zone")
@click.argument("cryptokey-id", type=click.INT)
def cryptokey_publish(ctx, dns_zone, cryptokey_id):
    """
    Publishes an already existing cryptokey. Implies activating it as well.
    """
    uri = (
        f"{ctx.obj['apihost']}"
        f"/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys/{cryptokey_id}"
    )
    payload = {
        "id": cryptokey_id,
        "published": True,
    }
    r = utils.does_cryptokey_exist(uri, f"Cryptokey with id {cryptokey_id} does not exist", 1, ctx)
    if r.json()["published"]:
        click.echo(json.dumps({"message": f"Cryptokey with id {cryptokey_id} already published"}))
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


@cryptokey.command("unpublish")
@click.pass_context
@click.argument("dns_zone", type=Zone, metavar="zone")
@click.argument("cryptokey-id", type=click.INT)
def cryptokey_unpublish(ctx, dns_zone, cryptokey_id):
    """
    Unpublishes an already existing cryptokey
    """
    uri = (
        f"{ctx.obj['apihost']}"
        f"/api/v1/servers/localhost/zones/{dns_zone}/cryptokeys/{cryptokey_id}"
    )
    payload = {
        "id": cryptokey_id,
        "published": False,
    }
    r = utils.does_cryptokey_exist(uri, f"Cryptokey with id {cryptokey_id} does not exist", 1, ctx)
    if not r.json()["published"]:
        click.echo(
            json.dumps({"message": f"Cryptokey with id {cryptokey_id} is already unpublished"})
        )
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


@cli.group()
@click.pass_context
def network(ctx):
    """Shows and sets up network views to limit access to dns entries"""
    if ctx.obj["major_version"] < 5:
        click.echo(json.dumps({"error": "Your authoritative dns-server does not support networks"}))
        raise SystemExit(1)


@network.command("add")
@click.argument("cidr", type=IPRange)
@click.argument("view_id", type=click.STRING, metavar="view")
@click.pass_context
def network_add(ctx, cidr, view_id):
    """
    Add a view of a zone to a specific network.
    Deleting requires passing an empty string to as view argument.
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/networks/{cidr}"
    current_network = utils.http_get(uri, ctx)
    if current_network.status_code == 200 and current_network.json()["view"] == view_id:
        click.echo(json.dumps({"message": f"Network {cidr} is already assigned to view {view_id}"}))
        raise SystemExit(0)
    payload = {"view": view_id}
    r = utils.http_put(uri, ctx, payload=payload)
    if utils.create_output(r, (204,), optional_json={"message": f"Added view {view_id} to {cidr}"}):
        raise SystemExit(0)
    raise SystemExit(1)


@network.command("list")
@click.pass_context
def network_list(ctx):
    """
    List all registered networks and views
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/networks"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@network.command("export")
@click.argument("cidr", type=IPRange)
@click.pass_context
def network_export(ctx, cidr):
    """
    Show the network and its associated views
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/networks/{cidr}"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@network.command("delete")
@click.argument("cidr", type=IPRange)
@click.pass_context
def network_delete(ctx, cidr):
    """
    Add a view of a zone to a specific network.
    Deleting requires passing an empty string to as view argument.
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/networks/{cidr}"
    current_network = utils.http_get(uri, ctx)
    if current_network.status_code == 404:
        click.echo(json.dumps({"message": f"Network {cidr} absent"}))
        raise SystemExit(0)
    payload = {"view": ""}
    r = utils.http_put(uri, ctx, payload=payload)
    if utils.create_output(
        r, (204,), optional_json={"message": f"Removed view association from {cidr}"}
    ):
        raise SystemExit(0)
    raise SystemExit(1)


@cli.group()
def record():
    """Resource records of a zone"""


@record.command("add")
@click.argument("name", type=click.STRING)
@click.argument("dns_zone", type=Zone, metavar="zone")
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
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{dns_zone}"
    name = utils.make_dnsname(name, dns_zone)
    rrset = {
        "name": name,
        "type": record_type.upper(),
        "ttl": ttl,
        "changetype": "REPLACE",
        "records": [{"content": content, "disabled": False}],
    }
    if utils.is_content_present(uri, ctx, rrset):
        click.echo(json.dumps({"message": f"{name} {record_type} {content} already present"}))
        raise SystemExit(0)

    r = utils.http_patch(uri, ctx, {"rrsets": [rrset]})
    if utils.create_output(
        r, (204,), optional_json={"message": f"{name} {record_type} {content} created"}
    ):
        raise SystemExit(0)
    raise SystemExit(1)


@record.command("delete")
@click.argument("name", type=click.STRING)
@click.argument("dns_zone", type=Zone, metavar="zone")
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
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{dns_zone}"
    if delete_all:
        rrset = {
            "name": name,
            "type": record_type.upper(),
            "ttl": ttl,
            "changetype": "DELETE",
            "records": [],
        }
        if not utils.is_matching_rrset_present(uri, ctx, rrset):
            click.echo(json.dumps({"message": f"{record_type} records in {name} already absent"}))
            raise SystemExit(0)
        r = utils.http_patch(uri, ctx, {"rrsets": [rrset]})
        msg = {"message": f"All {record_type} records for {name} removed"}
        if utils.create_output(r, (204,), optional_json=msg):
            raise SystemExit(0)
        msg = {"message": f"Failed to delete all {record_type} records for {name}"}
        click.echo(json.dumps(msg))
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
    if not utils.is_content_present(uri, ctx, rrset):
        msg = {"message": f"{name} {record_type} {content} already absent"}
        click.echo(json.dumps(msg))
        raise SystemExit(0)
    matching_rrsets = utils.is_matching_rrset_present(uri, ctx, rrset)
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
@click.argument("dns_zone", type=Zone, metavar="zone")
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
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{dns_zone}"

    rrset = {
        "name": name,
        "type": record_type.upper(),
        "ttl": ttl,
        "changetype": "REPLACE",
        "records": [{"content": content, "disabled": True}],
    }

    if utils.is_content_present(uri, ctx, rrset):
        msg = {"message": f"{name} IN {record_type} {content} already disabled"}
        click.echo(json.dumps(msg))
        raise SystemExit(0)
    rrset["records"] = utils.merge_rrsets(uri, ctx, rrset)
    r = utils.http_patch(uri, ctx, {"rrsets": [rrset]})
    msg = {"message": f"{name} IN {record_type} {content} disabled"}
    if utils.create_output(r, (204,), optional_json=msg):
        raise SystemExit(0)
    raise SystemExit(1)


# pylint: disable=unused-argument
@record.command("enable")
@click.argument("name", type=click.STRING)
@click.argument("dns_zone", type=Zone, metavar="zone")
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
@click.argument("dns_zone", type=Zone, metavar="zone")
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
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{dns_zone}"

    rrset = {
        "name": name,
        "type": record_type.upper(),
        "ttl": ttl,
        "changetype": "REPLACE",
        "records": [{"content": content, "disabled": False}],
    }
    if utils.is_content_present(uri, ctx, rrset):
        click.echo(json.dumps({"message": f"{name} IN {record_type} {content} already present"}))
        raise SystemExit(0)
    upstream_rrset = utils.is_matching_rrset_present(uri, ctx, rrset)
    if upstream_rrset:
        extra_records = [
            record
            for record in upstream_rrset["records"]
            if record["content"] != rrset["records"][0]["content"]
        ]
        rrset["records"].extend(extra_records)
    # breakpoint()
    r = utils.http_patch(uri, ctx, {"rrsets": [rrset]})
    msg = {"message": f"{name} IN {record_type} {content} extended"}
    if utils.create_output(r, (204,), optional_json=msg):
        raise SystemExit(0)
    raise SystemExit(1)


@record.command("export")
@click.argument("name", type=click.STRING)
@click.argument("dns_zone", type=Zone, metavar="zone")
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
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{dns_zone}"
    name = utils.make_dnsname(name, dns_zone)
    rrsets = utils.query_zone_rrsets(uri, ctx)
    for rrset in rrsets:
        if rrset["name"] == name and rrset["type"] == record_type.upper():
            click.echo(json.dumps(rrset))
            raise SystemExit(0)
    click.echo({"message": "Error, no rrset to export"})
    raise SystemExit(1)


@cli.group()
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
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/tsigkeys"
    payload = {"name": name, "algorithm": algorithm}
    if secret:
        payload["key"] = secret
    r = utils.http_get(f"{ctx.obj['apihost']}/api/v1/servers/localhost/tsigkeys/{name}", ctx)
    if r.status_code == 200 and secret:
        if r.json()["key"] == secret:
            msg = {"message": f"A TSIGKEY with {name} and your secret is already present"}
            click.echo(json.dumps(msg))
        raise SystemExit(0)
    if r.status_code == 200:
        msg = {"message": f"A TSIGKEY with name {name} is already present"}
        click.echo(json.dumps(msg))
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
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/tsigkeys/{name}"
    r = utils.http_get(uri, ctx)
    if not r.status_code == 200:
        msg = {"message": f"TSIGKEY for {name} already absent"}
        click.echo(json.dumps(msg))
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
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/tsigkeys/{key_id}"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@tsigkey.command("list")
@click.pass_context
def tsigkey_list(ctx):
    """
    Shows the TSIGKeys for this server
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/tsigkeys"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


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
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/tsigkeys/{name}"
    tsikey_settings = {
        k: v for k, v in {"algorithm": algorithm, "key": secret, "name": new_name}.items() if v
    }
    r = utils.http_get(uri, ctx)
    if r.status_code != 200:
        msg = {"message": f"Error, a TSIGKEY with name {name} does not exist"}
        click.echo(json.dumps(msg))
        raise SystemExit(1)
    if all(tsikey_settings[setting] == r.json()[setting] for setting in tsikey_settings):
        msg = {"message": f"The settings TSIGKEY {name} are already present"}
        click.echo(json.dumps(msg))
        raise SystemExit(0)
    if new_name:
        r = utils.http_get(f"{ctx.obj['apihost']}/api/v1/servers/localhost/tsigkeys", ctx)
        if new_name in (key["name"] for key in r.json()):
            msg = {"message": f"Error, the TSIGKEY {name} already exists. Refusing to rewrite."}
            click.echo(json.dumps(msg))
            raise SystemExit(1)
    r = utils.http_put(uri, ctx, tsikey_settings)
    if utils.create_output(
        r,
        (200,),
    ):
        raise SystemExit(0)
    raise SystemExit(1)


@cli.group()
def zone():
    """Manage zones"""


@zone.command("add")
@click.argument("dns_zone", type=Zone, metavar="zone")
@click.argument(
    "zonetype",
    type=click.Choice(["MASTER", "NATIVE"], case_sensitive=False),
)
@click.option(
    "-m",
    "--master",
    type=click.STRING,
    help="Set Zone Masters",
    default=None,
)
@click.pass_context
def zone_add(ctx, dns_zone, zonetype, master):
    """
    Adds a new zone. Can create a master or native zones, slaves zones are disabled
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones"
    if zonetype.upper() in ("MASTER", "NATIVE"):
        payload = {
            "name": dns_zone,
            "kind": zonetype.capitalize(),
            "masters": master.split(",") if master else [],
        }
    else:
        click.echo(json.dumps({"message": "Slave entries are not supported right now"}))
        raise SystemExit(1)
    current_zones = utils.query_zones(ctx)
    if [z for z in current_zones if z["name"] == dns_zone]:
        click.echo(json.dumps({"message": f"Zone {dns_zone} already present"}))
        raise SystemExit(0)
    r = utils.http_post(uri, ctx, payload)
    if utils.create_output(r, (201,), optional_json={"message": f"Zone {dns_zone} created"}):
        raise SystemExit(0)
    raise SystemExit(1)


@zone.command("delete")
@click.argument("dns_zone", type=Zone, metavar="zone")
@click.option(
    "-f",
    "--force",
    help="Force execution and skip confirmation",
    is_flag=True,
    default=False,
    show_default=True,
)
@click.pass_context
def zone_delete(ctx, dns_zone, force):
    """
    Deletes a Zone.
    """
    upstream_zones = utils.query_zones(ctx)
    if dns_zone not in [single_zone["name"] for single_zone in upstream_zones]:
        click.echo(json.dumps({"message": f"{dns_zone} already absent"}))
        raise SystemExit(0)

    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{dns_zone}"
    utils.confirm(
        f"!!!! WARNING !!!!!\n"
        f"You are attempting to delete {dns_zone}\n"
        f"Are you sure? [y/N] ",
        force,
    )
    r = utils.http_delete(uri, ctx)
    msg = {"message": f"{dns_zone} deleted"}
    if utils.create_output(r, (204,), optional_json=msg):
        raise SystemExit(0)
    raise SystemExit(1)


@zone.command("export")
@click.pass_context
@click.argument("dns_zone", type=Zone, metavar="zone")
@click.option(
    "-b",
    "--bind",
    help="Use bind format as output",
    is_flag=True,
    default=False,
)
def zone_export(ctx, dns_zone, bind):
    """
    Export the whole zone configuration, either as JSON or BIND
    """
    if bind:
        uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/export"
        r = utils.http_get(uri, ctx)
        if utils.create_output(r, (200,), output_text=True):
            raise SystemExit(0)
        raise SystemExit(1)
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{dns_zone}"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@zone.command("flush-cache")
@click.pass_context
@click.argument("dns_zone", type=Zone, metavar="zone")
def zone_flush_cache(ctx, dns_zone):
    """Flushes the cache of the given zone"""
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/cache/flush"
    r = utils.http_put(uri, ctx, params={"domain": dns_zone})
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@zone.command("notify")
@click.pass_context
@click.argument("dns_zone", type=Zone, metavar="zone")
def zone_notify(ctx, dns_zone):
    """
    Let the server notify its slaves of changes to the given zone

    Fails when the zone kind is neither master or slave, or master and slave are
    disabled in the configuration. Only works for slave if renotify is enabled.
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/notify"
    r = utils.http_put(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@zone.command("rectify")
@click.pass_context
@click.argument("dns_zone", type=Zone, metavar="zone")
def zone_rectify(ctx, dns_zone):
    """
    Rectifies a given zone. Will fail on slave zones and zones without dnssec.
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/rectify"
    r = utils.http_put(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@zone.command("search")
@click.argument("search-string", metavar="STRING")
@click.option("--max", "max_output", help="Number of items to output", default=5, type=click.INT)
@click.pass_context
def zone_search(ctx, search_string, max_output):
    """Do fulltext search in the rrset database. Use wildcards in your string to ignore leading
    or trailing characters"""
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/search-data"
    r = utils.http_get(
        uri,
        ctx,
        params={"q": f"{search_string}", "max": max_output},
    )
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@zone.command("list")
@click.pass_context
def zone_list(ctx):
    """
    Shows all configured zones on this dns server, does not display their RRSETs
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@cli.group()
def metadata():
    """Set up metadata for a zone"""


@metadata.command("add")
@click.argument("dns_zone", type=Zone, metavar="zone")
@click.argument("metadata-key", type=click.STRING)
@click.argument("metadata-value", type=click.STRING)
@click.pass_context
def metadata_add(ctx, dns_zone, metadata_key, metadata_value):
    """
    Adds metadata to a zone. Valid dictionary metadata-keys are not arbitrary and must conform
    to the expected content from the PowerDNS configuration. Custom metadata must be preceded by
    leading X- as a key
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/metadata"
    payload = {"kind": metadata_key, "metadata": [metadata_value], "type": "Metadata"}
    if utils.is_metadata_content_present(f"{uri}/{metadata_key}", ctx, payload):
        click.echo(
            json.dumps(
                {"message": f"{metadata_key} {metadata_value} in {dns_zone} already present"}
            )
        )
        raise SystemExit(0)
    r = utils.http_post(uri, ctx, payload)
    if utils.create_output(r, (201,)):
        raise SystemExit(0)
    raise SystemExit(1)


@metadata.command("delete")
@click.argument("dns_zone", type=Zone, metavar="zone")
@click.argument("metadata-key", type=click.STRING)
@click.pass_context
def metadata_delete(ctx, dns_zone, metadata_key):
    """
    Deletes a metadata entry for the given zone.
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/metadata/{metadata_key}"
    if utils.is_metadata_entry_present(uri, ctx):
        r = utils.http_delete(uri, ctx)
        if utils.create_output(
            r,
            (204, 200),
            optional_json={"message": f"Deleted metadata key {metadata_key} for {dns_zone}"},
        ):
            raise SystemExit(0)
        raise SystemExit(1)
    click.echo(json.dumps({"message": f"{metadata_key} for {dns_zone} already absent"}))
    raise SystemExit(0)


# pylint: disable=unused-argument
# noinspection PyUnusedLocal
@metadata.command("extend")
@click.argument("dns_zone", type=Zone, metavar="zone")
@click.argument("metadata-key", type=click.STRING)
@click.argument("metadata-value", type=click.STRING)
@click.pass_context
def metadata_extend(ctx, dns_zone, metadata_key, metadata_value):
    """
    Appends a new item to the list of metadata item for a zone
    """
    ctx.forward(metadata_add)


# pylint: enable=unused-argument


@metadata.command("list")
@click.argument("dns_zone", type=Zone, metavar="zone")
@click.option(
    "-l",
    "--limit",
    type=click.STRING,
    help="Limit metadata output to this single element",
)
@click.pass_context
def metadata_list(ctx, dns_zone, limit):
    """
    Lists the metadata for a given zone. Can optionally be limited to a single key
    """
    if limit:
        uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/metadata/{limit}"
    else:
        uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/metadata"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@metadata.command("update")
@click.argument("dns_zone", type=Zone, metavar="zone")
@click.argument("metadata-key", type=click.STRING)
@click.argument("metadata-value", type=click.STRING)
@click.pass_context
def metadata_update(ctx, dns_zone, metadata_key, metadata_value):
    """
    Replaces a set of metadata of a given zone
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{dns_zone}/metadata/{metadata_key}"
    payload = {"kind": metadata_key, "metadata": [metadata_value], "type": "Metadata"}
    if not utils.is_metadata_content_identical(uri, ctx, payload):
        r = utils.http_put(uri, ctx, payload)
        if utils.create_output(r, (200,)):
            raise SystemExit(0)
        raise SystemExit(1)
    click.echo(
        json.dumps({"message": f"{metadata_key}:{metadata_value} for {dns_zone} already present"})
    )
    raise SystemExit(0)


@cli.command("version")
def print_version():
    """Show the powerdns-cli version"""
    # pylint: disable-next=import-outside-toplevel
    import importlib

    click.echo(json.dumps({"version": importlib.metadata.version("powerdns-cli")}))


@cli.group()
@click.pass_context
def view(ctx):
    """Set view to limit zone access"""
    if ctx.obj["major_version"] < 5:
        click.echo(json.dumps({"error": "Your authoritative dns-server does not support views"}))
        raise SystemExit(1)


@view.command("add")
@click.argument("view_id", type=click.STRING, metavar="view")
@click.argument("dns_zone", type=Zone, metavar="zone")
@click.pass_context
def view_add(ctx, view_id, dns_zone):
    """Add a zone to a view, creates the view if it did not exist beforehand"""
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/views/{view_id}"
    view_content = utils.http_get(uri, ctx)
    if view_content.status_code == 200 and dns_zone in view_content.json()["zones"]:
        click.echo(json.dumps({"message": f"{dns_zone} already in {view_id}"}))
        raise SystemExit(0)
    payload = {"name": f"{dns_zone}"}
    r = utils.http_post(uri, ctx, payload=payload)
    if utils.create_output(r, (204,), optional_json={"message": f"Added {dns_zone} to {view_id}"}):
        raise SystemExit(0)
    raise SystemExit(1)


@view.command("delete")
@click.argument("view_id", type=click.STRING, metavar="view")
@click.argument("dns_zone", type=Zone, metavar="zone")
@click.pass_context
def view_delete(ctx, view_id, dns_zone):
    """Deletes a view"""
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/views/{view_id}"
    view_content = utils.http_get(uri, ctx)
    if view_content.status_code == 200 and dns_zone not in view_content.json()["zones"]:
        click.echo(json.dumps({"message": f"Zone {dns_zone} is not in {view_id}"}))
        raise SystemExit(0)
    if view_content.status_code == 404:
        click.echo(json.dumps({"message": f"View {view_id} is absent"}))
        raise SystemExit(0)
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/views/{view_id}/{dns_zone}"
    r = utils.http_delete(uri, ctx)
    if utils.create_output(
        r, (204,), optional_json={"message": f"Deleted {dns_zone} from {view_id}"}
    ):
        raise SystemExit(0)
    raise SystemExit(1)


@view.command("export")
@click.argument("view_id", type=click.STRING, metavar="view")
@click.pass_context
def view_export(ctx, view_id):
    """
    Exports a single view for its configured zones
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/views/{view_id}"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@view.command("list")
@click.pass_context
def view_list(ctx):
    """
    Shows all views and their configuration as a list
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/views"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


# pylint: disable=unused-argument
@view.command("update")
@click.argument("view_id", type=click.STRING, metavar="view")
@click.argument("dns_zone", type=Zone, metavar="zone")
@click.pass_context
def view_update(ctx, view_id, dns_zone):
    """Update a view to contain the given zone"""
    ctx.forward(view_add)


# pylint: enable=unused-argument


def main():
    """Main entrypoint to the cli application"""
    cli(auto_envvar_prefix="POWERDNS_CLI")


if __name__ == "__main__":
    main()
