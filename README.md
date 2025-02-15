[![PyPi version](https://badgen.net/pypi/v/powerdns-cli/)](ttps://pypi.org/project/powerdns-cli/)
[![GitHub latest commit](https://badgen.net/github/last-commit/IamLunchbox/powerdns-cli)](https://github.com/IamLunchbox/powerdns-cli/commits)
![Integration Test](https://github.com/IamLunchbox/powerdns-cli/actions/workflows/integration.yml/badge.svg)

# powerdns-cli
PowerDNS-CLI is your (scriptable) interface to interact with the
[PowerDNS Authoritative Nameserver](https://doc.powerdns.com/authoritative/).

This project is currently in alpha phase and will soon progress to a beta stage.
Beta release will be done as soon as integration tests and python version tests
are successful.

## Installation
Installation is available through pypi.org:

`pip install powerdns-cli`

Or you use this repositories-main branch for the latest version:

```shell
git clone https://github.com/IamLunchbox/powerdns-cli
python3 powerdns-cli/powerdns_cli/powerdns_cli.py
```

Please be advised, that the main branch, especially in alpha phase, might be
an in an unstable phase. Once this project progresses to a beta or production-
ready release you can expect the main branch to be stable, since changes will
stay in different branches.

## Usage
`powerdns-cli` is built with pythons click framework and uses keyword-based functions.
Therefore, shared flags, as the api key and api url, are positional.  

To get things going you may, for example, add a zone:  
`$ powerdns-cli -a MyApiKey -u http://localhost add-zone example.com. 10.0.0.1 MASTER`

The following example does **not** work and will create an error:  
`$ powerdns-cli add-zone -a MyApiKey -u http://localhost example.com. 10.0.0.1 MASTER`


You may provide all flags through your environment variables as well. Use the long
flag name in upper-case and prefix it with `POWERDNS_CLI_`. For example:

```shell
# This is effecively the same as above
export POWERDNS_CLI_APIKEY="MyApiKey"
export POWERDNS_CLI_URL="http://localhost"
powerdns-cli add-zone example.com. 10.0.0.1 MASTER
```

If you want to use environment variables for subcommands you will have to add
the subcommand to the variable string as well:  
`POWERDNS_CLI_ADD_RECORD_TTL=86400`.

`powerdns-cli` will almost always respond in json, even if the PowerDNS-api doesn't
(sometimes its plain/text, sometimes there is no output at all).
The only time you'll be provided with non-json output is, when you request a
BIND/AFXR-format export.

This script tries to stay idempotent
### Basic Examples
```shell
# Add a zone
$ powerdns-cli add-zone example.com. 10.0.0.1 MASTER
{"message": "Zone example.com. created"}
```

If you are in need of all the possible cli options, you can take a look
at the [integration test](https://github.com/IamLunchbox/powerdns-cli/blob/main/.github/workflows/integration.yml).
The workflow uses all the possible options to test for the api compatibility.

### Constraints
Building a simple cli for a large set of options of an api is no easy task.
Therefore, I had to go for compromises to keep `powerdns-cli` clutter-free.

But you should possibly want to know about these caveats:
1. It is not possible to simply create a record with several entries. Instead, you have to use `extend-record` several times.
2. If you want to remove a single entry from a multi-entry record, use `delete-record`. The other records are kept.
3. If you want to get rid of all the records all at once, you may pass `--all/-a` to `delete-record`.
4. There are no guardrails for removing records from a zone, only for removing a zone altogether.
5. By default, each record is enabled. You can disable a record, but enabling it requires re-adding it.
6. Disabled records don't appear in BIND-exports (hidden by PowerDNS).
7. The default TTL is set to 3600. You can (currently) not change the TTL after you set it in a rrset, you must recreate the record.

## Version Support
All the PowerDNS authoritative nameserver versions, which receive
patches / security updates, are covered by integration tests. You can check if
your version gets updates [here](https://doc.powerdns.com/authoritative/appendices/EOL.html).
And you can check [here](https://github.com/IamLunchbox/powerdns-cli/blob/main/.github/workflows/integration.yml) which versions are actually tested.

If the PowerDNS-Team does not apply releases and changes to their publicly
released docker images (see [here](https://hub.docker.com/r/powerdns/)), they
won't be covered by the integration tests.

## Todos
The following things are on my roadmap before a beta release:
1. Finish feature implementations and their integration tests
2. Rewrite the action keywords to simplify interaction (as in docker run, docker exec...) 
3. Allow updating TTLs
4. Version tests in tox

After the beta is done, i plan to port the code to implement it in ansible.
1. PowerDNS ansible module which has similar features to this one
2. unit-tests - possibly in conjunction with 4

Implemented features are:
- Everything around zone manipulation (creating zones, records and so forth)
- Exporting and searching current zone configuration
- Accessing server configuration and statistics
- Managing TSIG-Keys
- Zonemetadata

## API-Spec coverage

| Path          | Covered            | Planned            |
|---------------|--------------------|--------------------|
| autoprimaries | :heavy_check_mark: | :heavy_check_mark: |
| config        | :heavy_check_mark: | :heavy_check_mark: |
| search        | :heavy_check_mark: | :heavy_check_mark: |
| servers       | :x:                | :heavy_check_mark: |
| stats         | :heavy_check_mark: | :heavy_check_mark: |
| tsigkey       | :heavy_check_mark: | :heavy_check_mark: |
| zonecryptokey | :x:                | :heavy_check_mark: |
| zonemetadata  | :heavy_check_mark: | :heavy_check_mark: |
| zones         | Partly             | :heavy_check_mark: |
