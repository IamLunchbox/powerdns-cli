[![PyPi version](https://badgen.net/pypi/v/powerdns-cli/)](ttps://pypi.org/project/powerdns-cli/)
[![GitHub latest commit](https://badgen.net/github/last-commit/IamLunchbox/powerdns-cli)](https://github.com/IamLunchbox/powerdns-cli/commits)
![Integration Tests](https://github.com/IamLunchbox/powerdns-cli/actions/workflows/integration.yml/badge.svg)
![Unit Tests](https://github.com/IamLunchbox/powerdns-cli/actions/workflows/unit.yml/badge.svg)

# powerdns-cli
PowerDNS-CLI is a cli tool to interact with the
[PowerDNS Authoritative Nameserver](https://doc.powerdns.com/authoritative/). 
PowerDNS itself does only offer an API to interact with remotely and
its `pdns_util` does only work on the PowerDNS-Host, not remotely from another machine.
So, you may use this tool to work with your PowerDNS Authoritative Nameserver.

## Installation
Installation is available through pypi.org:

`pip install powerdns-cli`

Or as an oci container:  
`podman run --rm -it ghcr.io/IamLunchbox/powerdns-cli:latest powerdns-cli`

If you want to clone from git, checkout the git tags and run `pip install .`.

## Configuration
`powerdns-cli` is built with the click framework and uses keyword-based actions. Flags may 
only follow after the last action.  

To get things going you may, for example, add a zone:  
`$ powerdns-cli zone add -a MyApiKey -u http://localhost example.com PRIMARY`

You may provide all flags through environment variables as well. Use the long
flag name in upper-case and prefix it with `POWERDNS_CLI_`. For example:

```shell
$ export POWERDNS_CLI_APIKEY="MyApiKey"
$ export POWERDNS_CLI_URL="http://localhost"
$ powerdns-cli zone add example.com PRIMARY
```

It is also possible to set the common configuration items in `$HOME/.powerdns-cli.conf` or 
`$HOME/.config/powerdns-cli/configuration.toml`. The file format is `toml`, so you have to
explicitly use quotes for strings.  
This is the required structure and the defaults:  

```toml
apikey = ""
api-version = 4
debug = false
insecure = false
json = false
url = ""
```

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

If something goes wrong or does not work, use the `-j`-switch to get a more verbose json output.
This outputs includes some logging and a http-log, which might give you a hint what happened.  

For example:
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

For scripting purposes: It is always guaranteed, that `message` and `success` is set. If your
action requests data, as do `list` and `export`, it resides in `data`. Otherwise, `data` should be null.

When JSON is not requested, the stdout message will be the export contents.

If you are in need of all the possible cli options, you may also take a look
at the [integration test](https://github.com/IamLunchbox/powerdns-cli/blob/main/.github/workflows/integration.yml).
It uses all common cli options to test for api compatibility.

### Caveats
1. It is not possible to simply create a RRSet with several entries. Instead, you have to
   use `powerdns-cli record extend` or import a file.
2. There are no guardrails for removing records from a zone, only for removing a zone altogether.

## Version Support
All the PowerDNS authoritative nameserver versions, which receive
patches / security updates, are covered by integration tests. You can check if
your version gets updates [here](https://doc.powerdns.com/authoritative/appendices/EOL.html).
And you can check [here](https://github.com/IamLunchbox/powerdns-cli/blob/main/.github/workflows/integration.yml) which versions are actually tested.

If the PowerDNS-Team does not apply releases and changes to their publicly
released docker images (see [here](https://hub.docker.com/r/powerdns/)), they
won't be covered by the integration tests.
