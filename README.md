# powerdns-cli

A command line interface to interact with the
[Powerdns Authoritative Nameserver](https://doc.powerdns.com/authoritative/).

This project is currently in alpha phase and will soon progress to a beta stage.


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
