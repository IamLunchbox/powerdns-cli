# powerdns-cli

A command line interface to interact with the
[Powerdns Authoritative Nameserver](https://doc.powerdns.com/authoritative/).

This project is currently in alpha phase and will soon progress to a beta stage.
Beta release will be done as soon as integration tests and python version tests
are successful.


Implemented features are:
- Everything around zone manipulation (creating zones, records and so forth)
- Exporting and searching current zone configuration
- Accessing server configuration and statistics

Planned features are:
- Importing bind zone files
- Managing DNSSec-Keys

Features for the unforseeable future:
- Management specific for master / slave nodes

## Installation
Installation is available through pypi.org:

`pip install powerdns-cli`

Or you use this repositories-main branch for the latest version:

```shell
git clone https://github.com/IamLunchbox/powerdns-cli
python3 powerdns-cli/powerdns_cli/powerdns_cli.py
```

## Todos
Before further features are developed, the following things are on my roadmap:
1. Integration test through github-actions
2. Version tests in tox
3. A powerdns ansible modules which has similar features to this one
4. unit-tests - possibly in conjunction with 3


## API-Spec coverage

| Path          | Covered            | Planned            |
|---------------|--------------------|--------------------|
| autoprimary   | :x:                | :grey_question:    |
| config        | :heavy_check_mark: | :heavy_check_mark: |
| search        | :heavy_check_mark: | :heavy_check_mark: |
| servers       | :x:                | :grey_question:    |
| stats         | :heavy_check_mark: | :heavy_check_mark: |
| tsigkey       | :x:                | :heavy_check_mark: |
| zonecryptokey | :x:                | :heavy_check_mark: |
| zonemetadata  | :x:                | :grey_question:    |
| zones         | :heavy_check_mark: | :heavy_check_mark: |
