# Summary

The following repo contains a deployment utility written in Python that leverages a YAML configuration to easily abstract complex deployment procedures. It is designed to work equally-well as both an interactive "on-demand" script with useful stdout/stderr messages and a hands-off automation-ready script with filesystem logging and configurable reaction emails.

## Additional Features

* Extensive validation throughout the configuration process.
* Optional file logging.
* Optional email support.
* "Dry Run" support for parsing configurations and running rsync with `--dry-run`.
* Color output (with option to disable).
* Zero-dependancy binary option via [PyInstaller](https://pyinstaller.readthedocs.io/en/stable/operating-mode.html)!

## System Requirements

* Python 2.7
* [PyYAML](https://pyyaml.org/)
* `rsync` (used for transferring files)

For the all-in-one binary (see below):

* A 64-bit GNU/Linux operating system
* `rsync`

## Known Bugs & Potential Issues

* The optional arguement `--colo` coupled with the corresponding `colo` key within a YAML configuration is only supported for the action `rsync` and the action type `dst_srv`. 

----
## Usage

`deploy` is invoked with one required argument; the target 

The positional (required) and optional arguments:
```
positional arguments:
  target_spec                 Specifies the target to execute within the loaded configuration file.

optional arguments:
  -c DIR, --config-dir DIR    Specifies the directory within which the script will search for
                              configuration files. Defaults to a relative path called "conf".
  --colo COLO                 Specifies the destination servers (colo) for the loaded configuration
                              file. Defaults to "".
  -d, --dry-run               Specifies that the script should only execute a dry-run, preventing
                              any action specifications from actually executing.
  -e LVL, --email-level LVL   Specifies the condition at which the script should send an email,
                              being "never", "error", "warning", or "completion". Defaults to
                              "error".
  -t EMAIL, --email-to EMAIL  Specifies the email address to receive sent emails. This option is
                              ignored if "-e" is set to "never".
  --flyway-config FILE        Specifies the configuration file passed to the flyway utility when
                              handling MySQL migrations. Defaults to
                              "/opt/flyway-3.1/conf/migrations.properties".
  --flyway-executable FILE    Specifies a file path to the flyway executable utilized for MySQL
                              migrations. Defaults to "/opt/flyway-3.1/flyway".
  -h, --help                  Displays help and usage information.
  -f FILE, --log-file FILE    Specifies a log file to write to in addition to stdout/stderr.
                              Defaults to "/var/log/deploy.log".
  -l LVL, --log-level LVL     Specifies the log level of the script, being either "info" or "debug".
                              Defaults to "info".
  -m MODE, --log-mode MODE    Specifies whether to "append" or "overwrite" the specified log file.
                              Defaults to "append".
  --rsync-executable FILE     Specifies a file path to the rsync executable utilized for
                              transferring directories. Defaults to "/usr/bin/rsync".
  -s, --safe                  Specifies that the script should abort on any failed execution of an
                              action specification.
```

## Script Output

The output of a typical run may look something like this on sterr/stdout:

```
Validating working environment...
Loading selected configuration file...
[RSYNC] Deploying "/example/full/source/path/" to "/example/full/destination/path/" on "hostname1"...
[RSYNC] Deploying "/example/full/source/path/" to "/example/full/destination/path/" on "hostname2"...
[RSYNC] Deploying "/example/full/source/path/" to "/example/full/destination/path/" on "hostname3"...
[RSYNC] Deploying "/example/full/source/path/" to "/example/full/destination/path/" on "hostname4"...
[CMD] Executing "foobar"...
[CMD] Executing "foobar"...
[CMD] Executing "foobar"...
[CMD] Executing "foobar"...
[FLYWAY] Migrating "ExampleDatabase" on "hostname1"...
[FLYWAY] Migrating "ExampleDatabase" on "hostname2"...
[FLYWAY] Migrating "ExampleDatabase" on "hostname3"...
[FLYWAY] Migrating "ExampleDatabase" on "hostname4"...
Process completed! :)
```

The corresponding log file for the above run looks like this:
```
[INF] [02/04/2019 12:03:04] [25242] [deploy.validate_environment] Validating working environment...
[INF] [02/04/2019 12:03:04] [25242] [deploy.parse_config] Loading selected configuration file...
[INF] [02/04/2019 12:03:04] [25242] [deploy.perform_actions] [RSYNC] Deploying "/example/full/source/path/" to "/example/full/destination/path/" on "hostname1"...
[INF] [02/04/2019 12:03:04] [25242] [deploy.perform_actions] [RSYNC] Deploying "/example/full/source/path/" to "/example/full/destination/path/" on "hostname2"...
[INF] [02/04/2019 12:03:04] [25242] [deploy.perform_actions] [RSYNC] Deploying "/example/full/source/path/" to "/example/full/destination/path/" on "hostname3"...
[INF] [02/04/2019 12:03:04] [25242] [deploy.perform_actions] [RSYNC] Deploying "/example/full/source/path/" to "/example/full/destination/path/" on "hostname4"...
[INF] [02/04/2019 12:03:05] [25242] [deploy.perform_actions] [CMD] Executing "foobar"...
[INF] [02/04/2019 12:03:05] [25242] [deploy.perform_actions] [CMD] Executing "foobar"...
[INF] [02/04/2019 12:03:05] [25242] [deploy.perform_actions] [CMD] Executing "foobar"...
[INF] [02/04/2019 12:03:05] [25242] [deploy.perform_actions] [CMD] Executing "foobar"...
[INF] [02/04/2019 12:03:06] [25242] [deploy.perform_actions] [FLYWAY] Migrating "ExampleDatabase" on "hostname1"...
[INF] [02/04/2019 12:03:06] [25242] [deploy.perform_actions] [FLYWAY] Migrating "ExampleDatabase" on "hostname2"...
[INF] [02/04/2019 12:03:06] [25242] [deploy.perform_actions] [FLYWAY] Migrating "ExampleDatabase" on "hostname3"...
[INF] [02/04/2019 12:03:06] [25242] [deploy.perform_actions] [FLYWAY] Migrating "ExampleDatabase" on "hostname4"...
Process completed! :)
```
Notice that the log file follows the following format:

```
[LOG_LEVEL] [TIMESTAMP] [PROCESS_ID] [MODULE.FUNCTION] MESSAGE
```

## All-In-One Executable Binary

`deploy` may also be bundled into an all-in-one executable binary file by leveraging the [PyInstaller](https://pyinstaller.readthedocs.io/en/stable/operating-mode.html) executable packaging system. These binaries only require a 64-bit *nix environment to run.

