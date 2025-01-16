#!/usr/bin/env python3
"""
powerdns-cli: Manage PowerDNS Zones/Records
"""

import json
import sys
from typing import Literal

import click
import requests


# create click command group with 3 global options
@click.group(context_settings={'help_option_names': ['-h', '--help']})
@click.option(
    '-a',
    '--apikey',
    help='Provide your apikey manually',
    type=click.STRING,
    default=None,
    required=True
)
@click.option(
    '-u',
    '--url',
    help='DNS servers api url',
    type=click.STRING,
    required=True
)
@click.option(
    '-f',
    '--force',
    help='Force execution and skip confirmations',
    is_flag=True,
    default=False,
    show_default=True,
)
@click.option(
    '-k',
    '--insecure',
    help='Ignore invalid certificates',
    is_flag=True,
    default=False,
    show_default=True,
)
@click.pass_context
def cli(ctx, apikey, url, force, insecure):
    """Manage PowerDNS Authoritative Nameservers and their Zones/Records

    Your target server api must be specified through the corresponding cli-flags.
    You can also export them with the prefix POWERDNS_CLI_, for example:
    export POWERDNS_CLI_APIKEY=foobar
    """
    ctx.ensure_object(dict)
    ctx.obj['apihost'] = url
    ctx.obj['key'] = apikey
    ctx.obj['force'] = force

    session = requests.session()
    session.verify = insecure
    session.headers = {'X-API-Key': ctx.obj['key']}
    ctx.obj['session'] = session


# Add record
@cli.command()
@click.argument('name', type=click.STRING)
@click.argument('zone', type=click.STRING)
@click.argument(
    'record-type',
    type=click.Choice(
        [
            'A',
            'AAAA',
            'CNAME',
            'MX',
            'NS',
            'PTR',
            'SOA',
            'SRV',
            'TXT',
        ],
    ),
)
@click.argument('content', type=click.STRING)
@click.option('--ttl', default=3600, type=click.INT, help='Set default time to live')
@click.pass_context
def add_record(
    ctx,
    name,
    record_type,
    content,
    zone,
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
    zone = _make_canonical(zone)
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{zone}"
    name = _make_dnsname(name, zone)
    rrset = {
        'name': name,
        'type': record_type,
        'ttl': ttl,
        'changetype': 'REPLACE',
        'records': [
            {
                'content': content,
                'disabled': False
            }
        ],
    }
    if _traverse_rrsets(uri, rrset, 'is_content_present', ctx):
        click.echo(json.dumps({'message': f'{name} {record_type} {content} already exists'}))
        sys.exit(0)

    r = _http_patch(uri, {'rrsets': [rrset]}, ctx)
    if _create_output(r, 204,
                      optional_json={'message': f'{name} {record_type} {content} created'}):
        sys.exit(0)
    sys.exit(1)


@cli.command()
@click.argument('zone', type=click.STRING)
@click.argument('nameservers', type=click.STRING)
@click.argument(
    'zonetype',
    type=click.Choice(['MASTER', 'NATIVE'], case_sensitive=False),
)
@click.option(
    '-m',
    '--master',
    type=click.STRING,
    help='Set Zone Masters',
    default=None,
)
@click.pass_context
def add_zone(ctx, zone, nameservers, zonetype, master):
    """
    Adds a new zone

    Can create a master or native zone, slaves zones are disabled
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones"
    zone = _make_canonical(zone)
    if zonetype.upper() in ('MASTER', 'NATIVE'):
        payload = {
            'name': zone,
            'kind': zonetype.capitalize(),
            'masters': master.split(',') if master else [],
            'nameservers': [_make_canonical(server) for server in nameservers.split(',')],
        }
    else:
        click.echo(json.dumps({'error': 'Slave entries are not supported right now'}))
        sys.exit(1)
    current_zones = _query_zones(ctx)
    if [z for z in current_zones if z['name'] == zone]:
        click.echo(json.dumps({'message': f'Zone {zone} already present'}))
        sys.exit(1)
    r = _http_post(uri, payload, ctx)
    if _create_output(r, 201):
        sys.exit(0)
    sys.exit(1)


@cli.command()
@click.argument('name', type=click.STRING)
@click.argument('zone')
@click.argument(
    'record-type',
    type=click.Choice(
        [
            'A',
            'AAAA',
            'CNAME',
            'MX',
            'NS',
            'PTR',
            'SOA',
            'SRV',
            'TXT',
        ],
        case_sensitive=False,
    ),
)
@click.argument('content', type=click.STRING)
@click.option(
    '--ttl',
    default=3600,
    type=click.INT,
    help='Set default time to live')
@click.option(
    '-a',
    '-all',
    'delete_all',
    is_flag=True,
    default=False,
    help='Deletes all records of the selected type',)
@click.pass_context
def delete_record(ctx, name, zone, record_type, content, ttl, delete_all):
    """
    Deletes the DNS record of the given types and content

    If all is specified, all entries of given type and name will be removed

    Example:
    powerdns-cli delete_record mail example.org A 10.0.0.1
    """
    zone = _make_canonical(zone)
    name = _make_dnsname(name, zone)
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{zone}"
    if delete_all:
        rrset = {
            'name': name,
            'type': record_type,
            'ttl': ttl,
            'changetype': 'DELETE',
            'records': []
        }
        if not _traverse_rrsets(uri, rrset, 'matching_rrset', ctx):
            click.echo(json.dumps({'message': f'{record_type} record in {name} does not exist'}))
            sys.exit(0)
        r = _http_patch(uri, rrset, ctx)
        msg = {'message': f'All {record_type} records for {zone} removed'}
        if _create_output(r, 204, optional_json=msg):
            sys.exit(0)
        sys.exit(1)

    rrset = {
        'name': name,
        'type': record_type,
        'ttl': ttl,
        'changetype': 'REPLACE',
        'records': [
            {
                'content': content,
                'disabled': False,
            }
        ]
    }
    if not _traverse_rrsets(uri, rrset, 'is_content_present', ctx):
        msg = {'message': f'{name} {record_type} {content} already absent'}
        click.echo(json.dumps(msg))
        sys.exit(0)
    matching_rrsets = _traverse_rrsets(uri, rrset, 'matching_rrset', ctx)
    for index in range(len(matching_rrsets['records'])):
        if matching_rrsets['records'][index] == rrset['records'][0]:
            matching_rrsets['records'].pop(index)
    rrset['records'] = matching_rrsets['records']
    r = _http_patch(uri, {'rrsets': [rrset]}, ctx)
    msg = {'message': f'{name} {record_type} {content} removed'}
    if _create_output(r, 204, optional_json=msg):
        sys.exit(0)
    sys.exit(1)


@cli.command()
@click.argument('zone', type=click.STRING)
@click.pass_context
def delete_zone(ctx, zone):
    """
    Deletes a Zone
    """
    zone = _make_canonical(zone)
    upstream_zones = _query_zones(ctx)
    if zone not in [single_zone['id'] for single_zone in upstream_zones]:
        click.echo(json.dumps({'message': f'{zone} is not present'}))
        sys.exit(0)

    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{zone}"
    _confirm(
        f'!!!! WARNING !!!!!\n'
        f'You are attempting to delete {zone}\n'
        f'Are you sure? [Y/N] ',
        ctx,
    )
    r = _http_delete(uri, ctx)
    msg = {'message': f'Zone {zone} deleted'}
    if _create_output(r, 204, optional_json=msg):
        sys.exit(0)
    sys.exit(1)


# Disable record
@cli.command()
@click.argument('name', type=click.STRING)
@click.argument('zone', type=click.STRING)
@click.argument(
    'record-type',
    type=click.Choice(
        [
            'A',
            'AAAA',
            'CNAME',
            'MX',
            'NS',
            'PTR',
            'SOA',
            'SRV',
            'TXT',
        ],
    ),
)
@click.argument('content', type=click.STRING)
@click.option('--ttl', default=3600, type=click.INT, help='Set time to live')
@click.pass_context
def disable_record(
    ctx,
    name,
    record_type,
    content,
    zone,
    ttl,
):
    """
    Disable an existing DNS record.
    Use @ if you want to enter a record for the top level

    powerdns-cli disable_record test01 exmaple.org A 10.0.0.1
    """
    zone = _make_canonical(zone)
    name = _make_dnsname(name, zone)
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{zone}"

    rrset = {
                'name': name,
                'type': record_type,
                'ttl': ttl,
                'changetype': 'REPLACE',
                'records': [
                    {
                        'content': content,
                        'disabled': True
                    }
                ]
            }

    if _traverse_rrsets(uri, rrset, 'is_content_present', ctx):
        msg = {'message': f'{name} IN {record_type} {content} already disabled'}
        click.echo(json.dumps(msg))
        sys.exit(0)
    rrset['records'] = _traverse_rrsets(uri, rrset, 'merge_rrsets', ctx)
    r = _http_patch(uri, {'rrsets': [rrset]}, ctx)
    msg = {'message': f'{name} IN {record_type} {content} disabled'}
    if _create_output(r, 204, optional_json=msg):
        sys.exit(0)
    sys.exit(1)


# Extend record
@cli.command()
@click.argument('name', type=click.STRING)
@click.argument('zone', type=click.STRING)
@click.argument(
    'record-type',
    type=click.Choice(
        [
            'A',
            'AAAA',
            'CNAME',
            'MX',
            'NS',
            'PTR',
            'SOA',
            'SRV',
            'TXT',
        ],
    ),
)
@click.argument('content', type=click.STRING)
@click.option('--ttl', default=3600, type=click.INT, help='Set time to live')
@click.pass_context
def extend_record(
    ctx,
    name,
    record_type,
    content,
    zone,
    ttl,
):
    """
    Extends an existing new recordset.
    Will create a new record if it did not exist beforehand.
    """
    zone = _make_canonical(zone)
    name = _make_dnsname(name, zone)
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{zone}"

    rrset = {
                'name': name,
                'type': record_type,
                'ttl': ttl,
                'changetype': 'REPLACE',
                'records': [
                    {
                        'content': content,
                        'disabled': False
                    }
                ]
            }

    if _traverse_rrsets(uri, rrset, 'is_content_present', ctx):
        click.echo(json.dumps({'message': f'{name} IN {record_type} {content} already exists'}))
        sys.exit(0)
    upstream_rrset = _traverse_rrsets(uri, rrset, 'matching_rrset', ctx)
    extra_records = [
        record for record
        in upstream_rrset['records']
        if record['content'] != rrset['records'][0]['content']
    ]
    rrset['records'].extend(extra_records)
    r = _http_patch(uri, {'rrsets': [rrset]}, ctx)
    msg = {'message': f'{name} IN {record_type} {content} appended'}
    if _create_output(r, 204, optional_json=msg):
        sys.exit(0)
    sys.exit(1)


@cli.command()
@click.pass_context
@click.argument(
    'zone',
    type=click.STRING,
)
@click.option(
    '-b',
    '--bind',
    help='Use bind format as output',
    is_flag=True,
    default=False,
)
def export_zone(ctx, zone, bind):
    """
    Export the whole zone configuration
    """
    zone = _make_canonical(zone)
    if bind:
        uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{zone}/export"
        r = _http_get(uri, ctx)
        if _create_output(r, 200, output_text=True):
            sys.exit(0)
        sys.exit(1)
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{zone}"
    r = _http_get(uri, ctx)
    if _create_output(r, 200):
        sys.exit(0)
    sys.exit(1)


@cli.command()
@click.pass_context
def get_config(ctx):
    """
    Query PDNS Config
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/config"
    r = _http_get(uri, ctx)
    if _create_output(r, 200):
        sys.exit(0)
    sys.exit(1)


@cli.command()
@click.pass_context
def get_stats(ctx):
    """
    Query DNS Stats
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/statistics"
    r = _http_get(uri, ctx)
    if _create_output(r, 200):
        sys.exit(0)
    sys.exit(1)


@cli.command()
@click.pass_context
def list_zones(ctx):
    """
    Get all zones of dns server
    """
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones"
    r = _http_get(uri, ctx)
    if _create_output(r, 200):
        sys.exit(0)
    sys.exit(1)


@cli.command()
@click.pass_context
@click.argument(
    'zone',
    type=click.STRING,
)
def rectify_zone(ctx, zone):
    """
    Rectify a given zone

    Will fail on slave zones and zones without dnssec
    """
    zone = _make_canonical(zone)
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones/{zone}/rectify"
    r = ctx.obj['session'].put(uri)
    if _create_output(r, 200):
        sys.exit(0)
    sys.exit(1)


@cli.command()
@click.argument('search-string', metavar='STRING')
@click.option('--max', 'max_output', help='Number of items to output', default=5, type=click.INT,)
@click.pass_context
def search(ctx, search_string, max_output):
    """Do fulltext search in dns database"""
    uri = f"{ctx.obj['apihost']}/api/v1/servers/localhost/search-data"
    r = _http_get(
        uri,
        ctx,
        params={'q': f'*{search_string}*', 'max': max_output},
    )
    if _create_output(r, 200):
        sys.exit(0)
    sys.exit(1)


def _confirm(message: str, ctx: click.Context) -> None:
    """Confirmation function to keep users from doing potentially dangerous actions.
    Uses the force flag to determine if a manual confirmation is required."""
    if not ctx.obj['force']:
        click.echo(message)
        confirmation = input()
        if confirmation not in ('y', 'Y', 'YES', 'yes', 'Yes'):
            click.echo('Aborting')
            sys.exit(1)


def _create_output(
        content: requests.Response,
        exp_status_code: int,
        output_text: bool = False,
        optional_json: dict = None) -> bool:
    """Helper function to print a message in the appropriate format.
    Is needed since the powerdns api outputs different content types, not
    json all the time. Sometimes output is empty (each 204 response) or
    needs to be plain text - when you want to the BIND / AFXR export."""
    if content.status_code == exp_status_code and output_text:
        click.echo(content.text)
        return True
    if content.status_code == exp_status_code and optional_json:
        click.echo(json.dumps(optional_json))
        return True
    click.echo(json.dumps(content.json()))
    return False


def _http_delete(uri: str, ctx: click.Context, params: dict = None) -> requests.Response:
    """HTTP DELETE request"""
    try:
        request = ctx.obj['session'].delete(uri, params=params)
        return request
    except requests.RequestException as e:
        click.echo(json.dumps({'error': f'Request error: {e}'}))
        sys.exit(1)


def _http_get(uri: str, ctx: click.Context, params: dict = None) -> requests.Response:
    try:
        request = ctx.obj['session'].get(uri, params=params)
        return request
    except requests.RequestException as e:
        click.echo(json.dumps({'error': f'Request error: {e}'}))
        sys.exit(1)


def _http_patch(uri: str, rrset: dict, ctx: click.Context) -> requests.Response:
    try:
        request = ctx.obj['session'].patch(uri, json=rrset)
        return request
    except requests.RequestException as e:
        click.echo(json.dumps({'error': f'Request error: {e}'}))
        sys.exit(1)


def _http_post(uri: str, rrset: dict, ctx: click.Context) -> requests.Response:
    try:
        request = ctx.obj['session'].post(uri, json=rrset)
        return request
    except requests.RequestException as e:
        click.echo(json.dumps({'error': f'Request error: {e}'}))
        sys.exit(1)


def _query_zones(ctx) -> list:
    """Queries all zones of the dns server"""
    r = _http_get(f"{ctx.obj['apihost']}/api/v1/servers/localhost/zones", ctx)
    if r.status_code != 200:
        click.echo(json.dumps({'error': r.json()}))
        sys.exit(1)
    return r.json()


def _query_zone_rrsets(uri: str, ctx) -> list:
    """Queries the configuration of the given zone"""
    r = _http_get(uri, ctx)
    if r.status_code != 200:
        click.echo(json.dumps({'error': r.json()}))
        sys.exit(1)
    return r.json()['rrsets']


def _make_canonical(zone: str) -> str:
    """Returns the zone in caonical format with a trailing dot"""
    if not zone.endswith('.'):
        zone += '.'
    return zone


def _make_dnsname(name: str, zone: str) -> str:
    """Returns either the combination or zone
    or just a zone when @ is provided as name"""
    if name == '@':
        return zone
    return f'{name}.{zone}'


def _traverse_rrsets(
        uri: str,
        new_rrset: dict,
        query: Literal[
            'matching_rrset',
            'is_content_present',
            'merge_rrsets'],
        ctx):
    """Helper function to compare upstream and downstream rrsets / records"""
    zone_rrsets = _query_zone_rrsets(uri, ctx)
    if query == 'matching_rrset':
        for upstream_rrset in zone_rrsets:
            if all(upstream_rrset[key] == new_rrset[key] for key in ('name', 'type')):
                return upstream_rrset
        return {}
    if query == 'is_content_present':
        for rrset in zone_rrsets:
            # go through all the records to find matching rrset
            if (
                    all(rrset[key] == new_rrset[key] for key in ('name', 'type'))
                    and
                    all(entry in rrset['records'] for entry in new_rrset['records'])
            ):
                return True
        return False
    if query == 'merge_rrsets':
        merged_rrsets = new_rrset['records'].copy()
        for upstream_rrset in zone_rrsets:
            if all(upstream_rrset[key] == new_rrset[key] for key in ('name', 'type')):
                merged_rrsets.extend([record for record in upstream_rrset['records']
                                      if record['content'] != new_rrset['records'][0]['content']])
        return merged_rrsets
    return None


def main():
    """Main entrypoint to the cli application"""
    cli(auto_envvar_prefix='POWERDNS_CLI')


if __name__ == '__main__':
    main()
