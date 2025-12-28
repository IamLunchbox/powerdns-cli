[![PyPi version](https://badgen.net/pypi/v/powerdns-cli/)](ttps://pypi.org/project/powerdns-cli/)
[![GitHub latest commit](https://badgen.net/github/last-commit/IamLunchbox/powerdns-cli)](https://github.com/IamLunchbox/powerdns-cli/commits)
![Tests](https://github.com/IamLunchbox/powerdns-cli/actions/workflows/tests.yml/badge.svg)

# powerdns-cli
PowerDNS-CLI is a cli to interact with the
[PowerDNS Authoritative Nameserver](https://doc.powerdns.com/authoritative/). 
PowerDNS itself does only offer an API to interact with remotely and
its `pdns_util` does only work on the PowerDNS-Host, not from another machine.

## Installation
Installation is available through pypi.org:

`pip install powerdns-cli`

Or as an oci container:  
`podman run --rm -it ghcr.io/IamLunchbox/powerdns-cli:latest powerdns-cli`

To work with from git, checkout the repository and run `pip install .`.

## Configuration
`powerdns-cli` is built with the click framework and uses keyword-based actions. Flags may 
only follow after the last action keyword. To get things going, for example, add a zone:  
`$ powerdns-cli zone add -a MyApiKey -u http://localhost example.com PRIMARY`

All flags may alternatively be provided as environment variables. Each option must be prefixed
with `POWERDNS_CLI_` and the upper case setting. For example:

```shell
$ export POWERDNS_CLI_APIKEY="MyApiKey"
$ export POWERDNS_CLI_URL="http://localhost"
$ powerdns-cli zone add example.com PRIMARY
```

It is also possible to set the common configuration items in `./.powerdns-cli.conf`,
`$HOME/.powerdns-cli.conf` or `$HOME/.config/powerdns-cli/configuration.toml`. 
The file format is `toml`, so string have to explicitly quoted.
This is the required structure and their defaults, the option keys are not case sensitive:  

```toml
apikey = "mytestkey" # default is None
api-version = 4 # default is None
debug = false
insecure = false
json = false
server-id = "localhost"
timeout = 5
url = "http://example.com" # default is None
```

Only these settings can be accessed through the configuration file.

Depending on the context, for example editing records, further options may be available. Instead
of the flag, the corresponding env variable may be used. Since this cli directly accesses the 
default command class from click, **all** options reside under 
`POWERDNS_CLI_*`. So to set the TTL through the environment of `record add`, use 
`export POWERDNS_CLI_TTL=60`.

## Features
- Access to all API-Endpoints PowerDNS Auth exposes.
- CLI configuration through flags, environment variables or a configuration file.
- Exporting and importing data in JSON.
- Exporting RRSets in BIND.
- Idempotence.
- "Builtin" access to the current api-specification

## Usage
```shell
Usage: powerdns-cli [OPTIONS] COMMAND [ARGS]...

  Manage PowerDNS Authoritative Nameservers and their Zones/Records.

Options:
  -h, --help  Show this message and exit.

Commands:
  autoprimary  Change autoprimaries, which may modify this server.
  config       Show servers and their configuration
  cryptokey    Manage DNSSEC-Keys.
  metadata     Configure zone metadata.
  network      Set up networks views.
  record       Edit resource records (RRSets) of a zone.
  tsigkey      Set up server wide TSIGKeys, to sign transfer messages.
  version      Show the powerdns-cli version
  view         Configure views, which limit zone access based on IPs.
  zone         Manage zones and their configuration.
```

Refer to each action and its help page to find out more about each function.

### Examples

```shell
# Add a zone
$ powerdns-cli zone add example.org. native
Successfully created example.org.

# Add some records
$ powerdns-cli record add www example.org A 127.0.0.1
www.example.org. A 127.0.0.1 created.

$ powerdns-cli record add @ example.org MX "10 mail.example.org."
example.org. MX 10 mail.example.org. created.

# Import example.com from integration test
$ cat ./integration/import-zone.json | powerdns-cli zone import - 
Successfully added example.com..

# Delete zone, skipping confirmation
$ powerdns-cli zone delete example.com -f
Successfully deleted example.com..
```

If something goes wrong or does not work, the `-j`-switch provides more verbose output in json:
```shell
$ powerdns-cli record add  @ example.org MX "10 mail.test.de"  -j
[...]
        {
            "request": {
                "method": "PATCH",
                "url": "http://localhost:8082/api/v1/servers/localhost/zones/example.org."
            },
            "response": {
                "status_code": 422,
                "reason": "Unprocessable Entity",
                "json": {
                    "error": "Record example.org./MX '10 mail.test.de': Not in expected format (parsed as '10 mail.test.de.')"
                },
                "text": ""
            }
        }
    ],
    "data": null,
    "success": false,
    "message": "Failed to create example.org. MX 10 mail.test.de."
}
```

The [integration test](https://github.com/IamLunchbox/powerdns-cli/blob/main/.github/workflows/integration.yml) uses all common cli options to test for api compatibility.

### Scripting
- `message` and `success` are guaranteed to be set.
- `message` is emitted on stdout. It contains human readable output, except:
- If an action requests data, as do `list` and `export`, it resides in `data`. Otherwise, `data` is `null`.
- If an action requests data, `message` == `data` - so stdout will emit `data` as well.


### Caveats
1. It is not possible to simply create a RRSet with several entries. Instead, `powerdns-cli record add` needs to be used repeatedly.
2. Use `record replace` to ensure a RRSet has only a single value.
3. There are no guardrails for removing records from a zone, only for removing a zone altogether.

## Version Support
All the PowerDNS authoritative nameserver versions, which receive
patches / security updates, are covered by integration tests. Suported versions are documented [here](https://doc.powerdns.com/authoritative/appendices/EOL.html).
The integration tests cover the specified docker images [here](https://github.com/IamLunchbox/powerdns-cli/blob/main/.github/workflows/integration.yml).

If the PowerDNS-Team does not apply releases and changes to their publicly
released docker images (see [here](https://hub.docker.com/r/powerdns/)), they
won't be covered by the integration tests.
