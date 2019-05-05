#!/bin/env python2.7
'''
A Modular Deployment Script
'''

# ----- Python Library Imports -----

# Standard Library
import argparse
import glob
import logging
import os
import re
import shutil
import socket
import subprocess
import sys

# Additional Dependencies
import yaml

# Custom Modules
try:
  import emails
except ImportError as e:
  sys.exit('Unable to import email definitions - ' + str(e) + '.')

# ----------------------------------



# ----- Initialization -----

# A list of valid action types
ACTION_TYPES = [
    'cmd',
    'flyway',
    'rsync'
]

HELP_DESCRIPTION = """
A Modular Deployment Script
"""

HELP_EPILOG = """
"""

# Regular Expressions
range_regex = re.compile(r'^[a-zA-Z\d\-\.]+(?P<expr>\[(?P<lowerbound>\d+)\.\.(?P<upperbound>\d+)\])[a-zA-Z\d\-\.]*$')
comma_regex = re.compile(r'^[a-zA-Z\d\-\.]+(?P<expr>\[(?P<values>\d+(?:,\d+)+)\])[a-zA-Z\d\-\.]*$')
colo_regex = re.compile(r'(\{colo\.(\w+)\})')

# --------------------------



# ----- Private Functions -----

def _flyway(src_path, dst_db, dst_srv, flyway_args=''):
    '''
    Performs a mysql migration using the flyway utility.

    If the script is run in dry-run mode, the flyway utility will be run
    with the "info" command.
    '''
    if args.dry_run:
        flyway_command = 'info'
    else:
        flyway_command = 'migrate'
    flyway_config = '-configFile=' + args.flyway_config
    flyway_source = '-locations=filesystem:' + src_path
    flyway_dst = '-url=jdbc:mysql://{server}/{db}'.format(
        server = dst_srv,
        db = dst_db
    )
    cmd = '{flyway_exec} {config} {source} {args} {dst} {command}'.format(
        flyway_exec = args.flyway_executable,
        config = flyway_config,
        source = flyway_source,
        args = flyway_args,
        dst = flyway_dst,
        command = flyway_command
    )
    return _run_process(cmd)


def _get_dst_servers(dst_srv):
    '''
    Returns a list of servers corresponding to the expansion of an rsync action
    parameter specification.
    '''
    if not '[' in dst_srv and not ']' in dst_srv:
        return [dst_srv]
    if not ('[' in dst_srv and ']' in dst_srv):
        raise Exception('Mismatching square brackets in string')
    if '..' in dst_srv:
        range_match = range_regex.match(dst_srv)
        if not range_match:
            raise Exception('Unable to match regular expression of range')
        expr = range_match.group('expr')
        lb   = int(range_match.group('lowerbound'))
        ub   = int(range_match.group('upperbound'))
        servers = []
        for i in range(lb, ub + 1):
            servers.append(dst_srv.replace(expr, str(i)))
        return servers
    elif ',' in dst_srv:
        comma_match = comma_regex.match(dst_srv)
        if not comma_match:
            raise Exception('Unable to match regular expression of n-tuple')
        expr = comma_match.group('expr')
        values = comma_match.group('values')
        servers = []
        for i in values.split(','):
            servers.append(dst_srv.replace(expr, str(i)))
        return servers
    else:
        raise Exception('Expansion does not specify a range or n-tuple')


def _parse_arguments():
    '''
    Parses the command-line arguments into a global dictionary called "args".
    '''
    # Do some pre-parsing for some of the environment variables to prevent crashes
    if not os.getenv('DEPLOY_EMAIL_LVL', 'error') in ['never','error','warning','completion']:
        sys.exit('Invalid value set for environment variable "DEPLOY_EMAIL_LVL".')
    if not os.getenv('DEPLOY_LOG_LVL', 'info') in ['info', 'debug']:
        sys.exit('Invalid value set for environment variable "DEPLOY_LOG_LVL".')
    if not os.getenv('DEPLOY_LOG_MODE', 'append') in ['append', 'overwrite']:
        sys.exit('Invalid value set for environment variable "DEPLOY_LOG_MODE".')
    argparser = argparse.ArgumentParser(
        description = HELP_DESCRIPTION,
        epilog = HELP_EPILOG,
        usage = 'deploy TARGET_SPEC [...]',
        add_help = False,
        formatter_class = lambda prog: argparse.RawDescriptionHelpFormatter(prog, max_help_position=45, width=100)
    )
    # Positional argument
    argparser.add_argument(
        'target_spec',
        help = 'Specifies the target to execute within the loaded configuration file.'
    )
    argparser.add_argument(
        '-c',
        '--config-dir',
        default = os.getenv('DEPLOY_CONFIG_DIR','conf'),
        dest = 'config_dir',
        help = 'Specifies the directory within which the script will search for configuration files. Defaults to a relative path called "conf".',
        metavar = 'DIR'
    )
    argparser.add_argument(
        '--colo',
        default = '',
        dest = 'colo',
        help = 'Specifies the destination servers (colo) for the loaded configuration file. Defaults to "".',
        metavar = 'COLO'
    )
    argparser.add_argument(
        '-d',
        '--dry-run',
        action = 'store_true',
        dest = 'dry_run',
        help = 'Specifies that the script should only execute a dry-run, preventing any action specifications from actually executing.'
    )
    argparser.add_argument(
        '-e',
        '--email-level',
        choices = ['never', 'error', 'warning', 'completion'],
        default = os.getenv('DEPLOY_EMAIL_LVL', 'error'),
        dest = 'email_level',
        help = 'Specifies the condition at which the script should send an email, being "never", "error", "warning", or "completion". Defaults to "error".',
        metavar = 'LVL'
    )
    argparser.add_argument(
        '-t',
        '--email-to',
        default = os.getenv('DEPLOY_EMAIL_TO', 'example-email@example-email.com'),
        dest = 'email_to',
        help = 'Specifies the email address to receive sent emails. This option is ignored if "-e" is set to "never".',
        metavar = 'EMAIL'
    )
    argparser.add_argument(
        '--flyway-config',
        default = os.getenv('DEPLOY_FLYWAY_CONFIG', '/opt/flyway-3.1/conf/migrations.properties'),
        dest = 'flyway_config',
        help = 'Specifies the configuration file passed to the flyway utility when handling MySQL migrations. Defaults to "/opt/flyway-3.1/conf/migrations.properties".',
        metavar = 'FILE'
    )
    argparser.add_argument(
        '--flyway-executable',
        default = os.getenv('DEPLOY_FLYWAY_PATH', '/opt/flyway-3.1/flyway'),
        dest = 'flyway_executable',
        help = 'Specifies a file path to the flyway executable utilized for MySQL migrations. Defaults to "/opt/flyway-3.1/flyway".',
        metavar = 'FILE'
    )
    argparser.add_argument(
        '-h',
        '--help',
        action = 'help',
        help = 'Displays help and usage information.'
    )
    argparser.add_argument(
        '-f',
        '--log-file',
        default = os.getenv('DEPLOY_LOG_FILE', '/var/log/deploy.log'),
        dest = 'log_file',
        help = 'Specifies a log file to write to in addition to stdout/stderr. Defaults to "/var/log/deploy.log".',
        metavar = 'FILE'
    )
    argparser.add_argument(
        '-l',
        '--log-level',
        choices = ['info', 'debug'],
        default = os.getenv('DEPLOY_LOG_LVL', 'info'),
        dest = 'log_level',
        help = 'Specifies the log level of the script, being either "info" or "debug". Defaults to "info".',
        metavar = 'LVL'
    )
    argparser.add_argument(
        '-m',
        '--log-mode',
        choices = ['append', 'overwrite'],
        default = os.getenv('DEPLOY_LOG_MODE', 'append'),
        dest = 'log_mode',
        help = 'Specifies whether to "append" or "overwrite" the specified log file. Defaults to "append".',
        metavar = 'MODE'
    )
    argparser.add_argument(
        '--rsync-executable',
        default = os.getenv('DEPLOY_RSYNC_PATH', '/usr/bin/rsync'),
        dest = 'rsync_executable',
        help = 'Specifies a file path to the rsync executable utilized for transferring directories. Defaults to "/usr/bin/rsync".',
        metavar = 'FILE'
    )
    argparser.add_argument(
        '-s',
        '--safe',
        action = 'store_true',
        dest = 'safe',
        help = 'Specifies that the script should abort on any failed execution of an action specification.'
    )
    global args
    args = argparser.parse_args()


def _rsync(src, dst, rsync_args=''):
    '''
    Performs an rsync from the specified source path to the specified
    destination path.
    '''
    cmd = '{rsync_exec} {args} {src} {dst}'.format(
        rsync_exec = args.rsync_executable,
        args = rsync_args,
        src = src,
        dst = dst
    )
    return _run_process(cmd)


def _run_process(cmd, splitlines=True):
    '''
    Runs the specified command as a subprocess, returning the output of the
    command (optionally not split by lines) and its exit code.
    '''
    process = subprocess.Popen(
        cmd,
        stdout = subprocess.PIPE,
        stderr = subprocess.STDOUT,
        shell = True
    )
    output = process.communicate()[0]
    exit_code = process.returncode
    if splitlines:
        return (output.splitlines(), exit_code)
    else:
        return (output, exit_code)


def _send_email(subject, body, level='error', exception=None):
    '''
    Sends an email to the configured recipients with the specified body, subject,
    and alert level. Whether the email actually gets sent is dependent on the
    alert level specified by "args.email_level".
    '''
    if not level in ['error', 'warning', 'info']:
        raise Exception('Invalid email level: "' + str(level) + '"')
    if args.email_level == 'never' or (args.email_level == 'error' and level in ['warning', 'info']) or (args.email_level == 'warning' and level == 'info'):
        return
    else:
        if level == 'error':
            full_subject = 'ERROR: ' + subject
            if not exception is None:
                full_body = body + '\nBelow is the raised exception:\n' + str(exception)
            else:
                full_body = body
            full_body += '\n\nSee "' + args.log_file + '" on the machine for more details.'
        elif level == 'warning':
            full_subject = 'WARNING: ' + subject
            if not exception is None:
                full_body = body + '\nBelow is the raised exception:\n' + str(exception)
            else:
                full_body = body
            full_body += '\n\nSee "' + args.log_file + '" on the machine for more details.'
        else:
            full_subject = subject
            full_body = body
        with open('/tmp/deploy.email', 'w') as f:
            f.write('To: ' + args.email_to + '\n')
            f.write('Subject: ' + full_subject + '\n\n')
            f.write(full_body)
        with open(os.devnull, 'w') as DEVNULL:
            email_exit_code = subprocess.call('cat /tmp/deploy.email | /usr/sbin/sendmail -t', shell=True, stdout=DEVNULL, stderr=subprocess.STDOUT)
        if email_exit_code != 0:
            raise Exception('sendmail subprocess call returned non-zero exit code')
        else:
            return


def _setup_logging():
    '''
    Sets-up logging.
    '''
    try:
        if args.log_mode == 'append':
            logging_fmode = 'a'
        else:
            logging_fmode = 'w'
        if args.log_level == 'info':
            logging_level = logging.INFO
        else:
            logging_level = logging.DEBUG
        logging.basicConfig(
            filename = args.log_file,
            filemode = logging_fmode,
            level    = logging_level,
            format   = '[%(levelname)s] [%(asctime)s] [%(process)d] [%(module)s.%(funcName)s] %(message)s',
            datefmt  = '%m/%d/%Y %H:%M:%S'
        )
        logging.addLevelName(logging.CRITICAL, 'CRI')
        logging.addLevelName(logging.ERROR, 'ERR')
        logging.addLevelName(logging.WARNING, 'WAR')
        logging.addLevelName(logging.INFO, 'INF')
        logging.addLevelName(logging.DEBUG, 'DEB')
        log = logging.getLogger()
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setLevel(logging_level)
        class InfoFilter(logging.Filter):
            def filter(self, rec):
                return rec.levelno in (logging.DEBUG, logging.INFO)
        stdout_handler.addFilter(InfoFilter())
        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setLevel(logging.WARNING)
        log.addHandler(stdout_handler)
        log.addHandler(stderr_handler)
    except Exception as e:
        sys.exit('Unable to initialize logging system - ' + str(e) + '.')


# -----------------------------



# ----- Public Functions -----

def get_hostname():
    '''
    Obtains the hostname of the machine.
    '''
    logging.debug('Getting hostname...')
    try:
        global hostname
        hostname = socket.gethostname().split('.',1)[0]
    except Exception as e:
        logging.critical('Unable to discern hostname - ' + str(e) + '.')
        try:
            _send_email(
                subject = '? - Unable to discern hostname',
                body = emails.UNKNOWN_HOSTNAME,
                level = 'error',
                exception = e
            )
        except Exception as mail_e:
            logging.warning('Unable to send email - ' + str(mail_e) + '.')
        sys.exit(1)
    logging.debug('Hostname: ' + hostname)


def handle_colo(colo,dst_srv):
    '''
    Logic to handle if "colo" is present in the configuration file.
    Only supported for when the action is "rsync" and the action type is "dst_srv".
    '''
    if "{colo}" in dst_srv:
        logging.critical('A subtype such as "cmp_dst_srv" or "web_dst_srv" must be present.')
        send_email(
            'No subtype of "colo" was provided for dst_srv',
            emails.NO_SUBTYPE,
            'error'
        )
        sys.exit(4)
    # Handle colo only with preceding curly brace
    # and not for hostnames starting with "colo"
    elif '{colo.' in dst_srv:
        colo_match = colo_regex.findall(dst_srv)
        for m in colo_match:
            if not args.colo:
                logging.critical('The "--colo" command-line argument must be included if the dst_srv has {colo.*}.')
                send_email(
                    '"--colo" was not specified',
                    emails.NO_COLO_ARG,
                    'error'
                )
                sys.exit(4)
            else:
                # Where fs is full string
                fs = m[0]
                # Where ctype is the subtype
                ctype = m[1]
                if not ctype in colo[args.colo]:
                    logging.critical('The specified colo subtype does not exist in the corresponding colo.')
                    send_email(
                        'Failed to format colo subtypes',
                        emails.WRONG_SUBTYPE,
                        'error'
                    )
                    sys.exit(4)
                else:
                    repl_str = colo[args.colo][ctype]
                    return dst_srv.replace(fs,repl_str)
                    #logging.debug('Destination Servers:' + dst_srv)
    else:
        return dst_srv


def main():
    '''
    The entry point of the script.
    '''
    # Parse command-line arguments
    _parse_arguments()

    # Setup logging
    _setup_logging()

    # Log CLI arguments at the DEBUG level
    logging.debug('----- CLI Arguments -----')
    dargs = vars(args)
    for a in dargs:
        logging.debug(a + ' : ' + str(dargs[a]))
    logging.debug('-------------------------')

    # Get the hostname of the machine
    get_hostname()

    # Validating the execution environment
    validate_environment()

    # Parse the selected configuration file
    parse_config()

    # Perform the configured actions for the specified target
    perform_actions()

    # Completed!
    logging.info('Process completed! :)')
    send_email(
        'Deployment process complete',
        emails.COMPLETE,
        'info'
    )
    sys.exit(0)


def parse_config():
    '''
    Parses the selected configuration (YAML) file into a global dictionary.
    '''
    logging.info('Loading selected configuration file...')
    logging.debug('Reading selected configuration file...')
    try:
        with open(config_path, 'r') as f:
            raw_config = f.read()
    except Exception as e:
        logging.critical('Unable to read selected configuration file - ' + str(e) + '.')
        send_email(
            'Unable to load configuration file',
            emails.CANT_READ_CONFIG,
            'error',
             e
        )
        sys.exit(3)
    logging.debug('Parsing selected configuration file...')
    try:
        global config
        config = yaml.load(raw_config)
    except Exception as e:
        logging.critical('Unable to parse selected configuration file - ' + str(e) + '.')
        send_email(
            'Unable to load configuration file',
            emails.CANT_PARSE_CONFIG,
            'error',
            e
        )
        sys.exit(3)
    logging.debug('Parsed Config: ' + str(config))
    logging.debug('Validating configuration file...')
    if not 'targets' in config:
        logging.critical('Selected configuration file does not contain the required "targets" key.')
        send_email(
            'Unable to validate configuration file',
            emails.NO_TARGETS_KEY,
            'error'
        )
        sys.exit(3)
    # Parse config for 'colo'
    if 'colo' in config:
        if not isinstance(config['colo'], dict):
            logging.critical('"colo" key in selected configuration file does not correspond to a dictionary of colo specifications.')
            send_email(
                'Unable to validate configuration file',
                emails.COLO_NOT_DICT,
                'error'
            )
            sys.exit(3)
        # Ensure everything under "colo" is a dictionary
        for i in config['colo']:
            if not isinstance(config['colo'][i], dict):
                logging.critical('"colo" value in selected configuration file does not correspond to a dictionary of colo specifications.')
                send_email(
                    'Unable to validate configuration file',
                    emails.COLO_VALUE_NOT_DICT,
                    'error'
                )
                sys.exit(3)
    if not isinstance(config['targets'], dict):
        logging.critical('"targets" key in selected configuration file does not correspond to a dictionary of target specifications.')
        send_email(
            'Unable to validate configuration file',
            emails.TARGETS_NOT_DICT,
            'error'
        )
        sys.exit(3)
    if not args.target_spec in config['targets']:
        logging.critical('Provided target specification does not exist within the selected configuration file.')
        send_email(
            'Unable to validate configuration file',
            emails.TARGET_DOESNT_EXIST,
            'error'
        )
        sys.exit(3)
    global action_specs
    action_specs = config['targets'][args.target_spec]
    if not isinstance(action_specs, list):
        logging.critical('Provided target specification does not correspond to a list of action specifications.')
        send_email(
            'Unable to validate configuration file',
            emails.ACTION_SPECS_NOT_LIST,
            'error'
        )
        sys.exit(3)
    for spec in action_specs:
        if not isinstance(spec, dict):
            logging.critical('One or more action specifications are not dictionaries.')
            send_email(
                'Unable to validate configuration file',
                emails.ACTION_NOT_DICT,
                'error'
            )
            sys.exit(3)
        if not 'do' in spec:
            logging.critical('One or more action specifications do not define an action type.')
            send_email(
                'Unable to validate configuration file',
                emails.NO_ACTION_TYPE,
                'error'
            )
            sys.exit(3)
        if not spec['do'] in ACTION_TYPES:
            logging.critical('One or more action specifications do not define a valid action type (' + spec['do'] + ').')
            send_email(
                'Unable to validate configuration file',
                emails.INVALID_ACTION_TYPE,
                'error'
            )
            sys.exit(3)


def perform_actions():
    '''
    Performs all of the actions defined as action specifications within the
    selected target.
    '''
    # Pull out everything that isn't under the "targets" key into its own dict
    # for replacing stuff.
    conf_vars = config.copy()
    conf_vars.pop('targets', None)

    if 'colo' in config:
        colo = config['colo']
    else:
        colo = {}
    conf_vars.pop('colo', None)

    for action in action_specs:
        action_type = action['do']
        logging.debug('Action Type: ' + action_type)
        # ----- Handle Rsyncs -----
        if action_type == 'rsync':
            if not 'src_path' in action or not 'dst_path' in action or not 'dst_srv' in action:
                logging.critical('One or more rsync action specifications do not define the required action parameters.')
                send_email(
                    'Invalid rsync action specification',
                    emails.INVALID_RSYNC_SPEC,
                    'error'
                )
                sys.exit(4)
            try:
                # First, parse for colo
                dst_srv = handle_colo(colo,action['dst_srv'])
                logging.debug('dst_srv: ' + dst_srv)
                # Once "colo" is done, then format for conf_vars
                src_path = action['src_path'].format(**conf_vars)
                logging.debug('src_path: ' + src_path)
                dst_path = action['dst_path'].format(**conf_vars)
                logging.debug('dst_path: ' + dst_path)
                # Further format dst_srv if necessary
                dst_srv  = dst_srv.format(**conf_vars)
                logging.debug('dst_srv: ' + dst_srv)

                if 'extra_args' in action:
                    rsync_args = '-a -h --progress ' + action['extra_args'].format(**conf_vars)
                else:
                    rsync_args = '-a -h --progress'
            except Exception as e:
                logging.critical('One or more rsync action specifications failed to format one or more action parameters - ' + str(e) + '.')
                send_email(
                    'Failed to format rsync action parameters',
                    emails.INVALID_RSYNC_PARAMS,
                    'error',
                    e
                )
                sys.exit(4)
            logging.debug('Source Path: ' + src_path)
            logging.debug('Destination Path: ' + dst_path)
            logging.debug('Raw Destination Server(s): ' + dst_srv)
            logging.debug('Arguments: ' + rsync_args)
            try:
                dst_servers = _get_dst_servers(dst_srv)
            except Exception as e:
                logging.critical('One or more rsync action specifications have invalid values for "dst_srv" - ' + str(e) + '.')
                send_email(
                    'Failed to parse destination servers',
                    emails.INVALID_RSYNC_SRV,
                    'error',
                    e
                )
                sys.exit(4)
            logging.debug('Destination Server(s): ' + str(dst_servers))
            for server in dst_servers:
                if args.dry_run:
                    logging.info('[RSYNC (DRY RUN)] Deploying "' + src_path + '" to "' + dst_path + '" on "' + server + '"...')
                else:
                    logging.info('[RSYNC] Deploying "' + src_path + '" to "' + dst_path + '" on "' + server + '"...')
                try:
                    if not args.dry_run:
                        # We strip leading "/" characters to prevent issues.
                        true_dst = 'rsync://{server}/{path}'.format(server=server, path=dst_path.lstrip('/'))
                        logging.debug('Full rsync command: rsync ' + rsync_args + ' ' + src_path + ' ' + true_dst)
                        (rsync_output, rsync_exit_code) = _rsync(
                            src = src_path,
                            dst = true_dst,
                            rsync_args = rsync_args
                        )
                    else:
                        (rsync_output, rsync_exit_code) = ("DRY RUN", 0)
                except Exception as e:
                    if args.safe:
                        logging.critical('Unable to rsync to destination server - ' + str(e) + '.')
                        send_email(
                            'Unable to rsync to destination server',
                            emails.UNABLE_TO_RSYNC,
                            'error',
                            e
                        )
                        sys.exit(4)
                    else:
                        logging.warning('Unable to rsync to destination server - ' + str(e) + '.')
                        send_email(
                            'Unable to rsync to destination server',
                            emails.UNABLE_TO_RSYNC,
                            'warning',
                            e
                        )
                        continue
                logging.debug('Rsync Exit Code: ' + str(rsync_exit_code))
                if rsync_exit_code != 0:
                    if args.safe:
                        logging.critical('Unable to rsync to destination server - subprocess returned non-zero exit code.')
                        if rsync_output:
                            for l in rsync_output:
                                logging.critical('Rsync Output: ' + l)
                        send_email(
                            'Unable to rsync to destination server',
                            emails.UNABLE_TO_RSYNC,
                            'error'
                        )
                        sys.exit(4)
                    else:
                        logging.warning('Unable to rsync to destination server - subprocess returned non-zero exit code.')
                        if rsync_output:
                            for l in rsync_output:
                                logging.warning('Rsync Output: ' + l)
                        send_email(
                            'Unable to rsync to destination server',
                            emails.UNABLE_TO_RSYNC,
                            'warning'
                        )
                        continue
                else:
                    if rsync_output:
                            for l in rsync_output:
                                logging.debug('Rsync Output: ' + l)
        # ----- Handle Commands -----
        elif action_type == 'cmd':
            if not 'cmd' in action:
                logging.critical('One or more command action specifications do not define the required action parameters.')
                send_email(
                    'Invalid command action specification',
                    emails.INVALID_CMD_SPEC,
                    'error'
                )
                sys.exit(4)
            try:
                cmd = action['cmd'].format(**conf_vars)
            except Exception as e:
                logging.critical('Unable to format command action specification command string.')
                send_email(
                    'Unable to format command action specification command string',
                    emails.INVALID_CMD_CMD,
                    'error'
                )
                sys.exit(4)
            if args.dry_run:
                logging.info('[CMD (DRY RUN)] Executing "' + cmd + '"...')
            else:
                logging.info('[CMD] Executing "' + cmd + '"...')
            try:
                if not args.dry_run:
                    (command_output, command_exit_code) = _run_process(cmd)
                else:
                    (command_output, command_exit_code) = ("DRY RUN", 0)
            except Exception as e:
                if args.safe:
                    logging.critical('Error executing command - ' + str(e) + '.')
                    send_email(
                        'Unable to execute command',
                        emails.UNABLE_TO_CMD,
                        'error',
                        e
                    )
                    sys.exit(4)
                else:
                    logging.warning('Error executing command - ' + str(e) + '.')
                    send_email(
                        'Unable to execute command',
                        emails.UNABLE_TO_CMD,
                        'warning',
                        e
                    )
                    continue
            logging.debug('Command Exit Code: ' + str(command_exit_code))
            if command_exit_code != 0:
                if args.safe:
                    logging.critical('Error executing command - subprocess returned non-zero exit code.')
                    if command_output:
                        for l in command_output:
                            logging.critical('Command Output: ' + l)
                    send_email(
                        'Unable to execute command',
                        emails.UNABLE_TO_CMD,
                        'error'
                    )
                    sys.exit(4)
                else:
                    logging.warning('Error executing command - subprocess returned non-zero exit code.')
                    if command_output:
                        for l in rsync_output:
                            logging.warning('Command Output: ' + l)
                    send_email(
                        'Unable to execute command',
                        emails.UNABLE_TO_CMD,
                        'warning'
                    )
                    continue
            else:
                if command_output:
                    for l in command_output:
                        logging.debug('Command Output: ' + l)
        # ----- Handle MySQL Migrations (via flyway) -----
        elif action_type == 'flyway':
            if not os.path.isfile(args.flyway_executable):
                logging.critical('Specified flyway executable path does not exist.')
                send_email(
                    'Unable to validate environment',
                    emails.FLYWAY_DOESNT_EXIST,
                    'error'
                )
                sys.exit(2)
            if not os.path.isfile(args.flyway_config):
                logging.critical('Specified flyway configuration file does not exist.')
                send_email(
                    'Unable to validate environment',
                    emails.FLYWAY_CONFIG_DOESNT_EXIST,
                    'error'
                )
                sys.exit(2)
            if not 'src_path' in action or not 'dst_db' in action or not 'dst_srv' in action:
                logging.critical('One or more flyway action specifications do not define the required action parameters.')
                send_email(
                    'Invalid flyway action specification',
                    emails.INVALID_FLYWAY_SPEC,
                    'error'
                )
                sys.exit(4)
            try:
                src_path = action['src_path'].format(**conf_vars)
                dst_db   = action['dst_db'].format(**conf_vars)
                dst_srv  = action['dst_srv'].format(**conf_vars)
                if 'extra_args' in action:
                    flyway_args = action['extra_args'].format(**conf_vars)
                else:
                    flyway_args = ''
            except Exception as e:
                logging.critical('One or more flyway action specifications failed to format one or more action parameters - ' + str(e) + '.')
                send_email(
                    'Failed to format flway action parameters',
                    emails.INVALID_FLYWAY_PARAMS,
                    'error',
                    e
                )
                sys.exit(4)
            logging.debug('Source Path: ' + src_path)
            logging.debug('Destination Database: ' + dst_db)
            logging.debug('Raw Destination Server(s): ' + dst_srv)
            logging.debug('Arguments: ' + flyway_args)
            if '-configFile' in flyway_args or '-locations' in flyway_args or '-url' in flyway_args:
                logging.critical('One or more flyway action specifications define additional arguments which conflict with this script\'s internal mechanisms.')
                send_email(
                    'Conflicting flyway arguments',
                    emails.CONFLICTING_FLYWAY_ARGS,
                    'error'
                )
                sys.exit(4)
            try:
                dst_servers = _get_dst_servers(dst_srv)
            except Exception as e:
                logging.critical('One or more flyway action specifications have invalid values for "dst_srv" - ' + str(e) + '.')
                send_email(
                    'Failed to parse destination servers',
                    emails.INVALID_FLYWAY_SRV,
                    'error',
                    e
                )
                sys.exit(4)
            logging.debug('Destination Server(s): ' + str(dst_servers))
            for server in dst_servers:
                if args.dry_run:
                    logging.info('[FLYWAY (DRY RUN)] Migrating "' + dst_db + '" on "' + server + '"...')
                else:
                    logging.info('[FLYWAY] Migrating "' + dst_db + '" on "' + server + '"...')
                try:
                    (flyway_output, flyway_exit_code) = _flyway(
                        src_path = src_path,
                        dst_db = dst_db,
                        dst_srv = server,
                        flyway_args = flyway_args
                    )
                except Exception as e:
                    if args.safe:
                        logging.critical('Unable to perform MySQL migration - ' + str(e) + '.')
                        send_email(
                            'Unable to perform MySQL migration',
                            emails.UNABLE_TO_FLYWAY,
                            'error',
                            e
                        )
                        sys.exit(4)
                    else:
                        logging.warning('Unable to perform MySQL migration - ' + str(e) + '.')
                        send_email(
                            'Unable to perform MySQL migration',
                            emails.UNABLE_TO_FLYWAY,
                            'warning',
                            e
                        )
                        continue
                logging.debug('Flyway Exit Code: ' + str(flyway_exit_code))
                if flyway_exit_code != 0:
                    if args.safe:
                        logging.critical('Unable to perform MySQL migration - subprocess returned non-zero exit code.')
                        if flyway_output:
                            for l in flyway_output:
                                logging.critical('Flyway Output: ' + l)
                        send_email(
                            'Unable to perform MySQL migration',
                            emails.UNABLE_TO_FLYWAY,
                            'error'
                        )
                        sys.exit(4)
                    else:
                        logging.warning('Unable to perform MySQL migration - subprocess returned non-zero exit code.')
                        if flyway_output:
                            for l in flyway_output:
                                logging.warning('Flyway Output: ' + l)
                        send_email(
                            'Unable to perform MySQL migration',
                            emails.UNABLE_TO_FLYWAY,
                            'warning'
                        )
                        continue
                else:
                    if flyway_output:
                            for l in flyway_output:
                                logging.debug('Flyway Output: ' + l)
        # ----- Done Handling Actions -----


def send_email(subject, body, level='error', exception=None):
    '''
    Sends an email to the configured recipients with the specified body, subject,
    and alert level. Whether the email actually gets sent is dependent on the
    alert level specified by "args.email_level".
    '''
    try:
        _send_email(hostname + ' - ' + subject, body, level, exception)
    except Exception as mail_e:
        logging.warning('Unable to send email - ' + str(mail_e) + '.')

def validate_environment():
    '''
    Validates the execution environment.

    Note that we don't validate "--flyway-config" or "--flyway-executable" since
    not all environments leverage the flyway utility for mysql migrations.
    '''
    logging.info('Validating working environment...')
    logging.debug('Validating rsync executable path...')
    if not os.path.isfile(args.rsync_executable):
        logging.critical('Specified rsync executable path does not exist.')
        send_email(
            'Unable to validate environment',
            emails.RSYNC_DOESNT_EXIST,
            'error'
        )
        sys.exit(2)
    logging.debug('Validating specified configuration directory...')
    if not os.path.isdir(args.config_dir):
        logging.critical('Specified configuration directory: ' + args.config_dir  + ' does not exist.')
        send_email(
            'Unable to validate environment',
            emails.CONFIG_DIR_DOESNT_EXIST,
            'error'
        )
        sys.exit(2)
    logging.debug('Selecting relevant configuration path...')
    global config_path
    config_path = os.path.join(args.config_dir, hostname  + '.yaml')
    logging.debug('Selected configuration path:' + config_path)
    if not os.path.isfile(config_path):
       logging.critical('Selected configuration path: ' + config_path + ' does not exist.')
       send_email(
            'Unable to validate environment',
            emails.CONFIG_PATH_DOESNT_EXIST,
            'error'
       )
       sys.exit(2)


# ----------------------------



# ----- Boilerplate Magic -----

if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, EOFError) as ki:
        sys.stderr.write('Recieved keyboard interrupt!\n')
        sys.exit(100)

# -----------------------------

