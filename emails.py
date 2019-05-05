'''
Contains email bodies for the deploy script.
'''

PRE_MSG = 'The deployment script reports that'

ACTION_NOT_DICT = """
{pre} one or more action specifications in the provided target specification do not correspond to a dictionary of action parameters.
""".format(pre=PRE_MSG)

ACTION_SPECS_NOT_LIST = """
{pre} the provided target specification does not correspond to a list of action specifications.
""".format(pre=PRE_MSG)

CANT_PARSE_CONFIG = """
{pre} it encountered an exception while trying to parse the selected configuration file.
""".format(pre=PRE_MSG)

CANT_READ_CONFIG = """
{pre} it encountered an exception while trying to read the selected configuration file.
""".format(pre=PRE_MSG)

COLO_NOT_DICT = """
{pre} the provided colo key does not correspond to a dictionary of colo specifications.
""".format(pre=PRE_MSG)

COLO_VALUE_NOT_DICT = """
{pre} the provided colo value does not correspond to a dictionary of colo specifications.
""".format(pre=PRE_MSG)

COMPLETE = """
{pre} the deployment process completed without errors.
""".format(pre=PRE_MSG)

CONFIG_DIR_DOESNT_EXIST = """
{pre} the specified configuration directory does not exist on the local filesystem.
""".format(pre=PRE_MSG)

CONFLICTING_FLYWAY_ARGS = """
{pre} one or more flyway action specifications in the provided target specification have specified additional flyway arguments which conflict with the script's internal mechanisms.
Do not specify "-configFile", "-locations", or "-url" in the "flyway_args" action parameter.
""".format(pre=PRE_MSG)

INVALID_ACTION_TYPE = """
{pre} one or more action specifications in the provided target specification do not define a valid action type.
""".format(pre=PRE_MSG)

INVALID_CMD_CMD = """
{pre} it encountered an exception while trying to format a command action specification's command string.
""".format(pre=PRE_MSG)

INVALID_CMD_SPEC = """
{pre} one or more command action specifications in the provided target specification do not define the required action parameters.
""".format(pre=PRE_MSG)

INVALID_FLYWAY_PARAMS = """
{pre} it failed to format one or more flyway action parameters in the provided target specification.
""".format(pre=PRE_MSG)

INVALID_FLYWAY_SPEC = """
{pre} one or more flyway action specifications in the provided target specification do not define the required action parameters.
""".format(pre=PRE_MSG)

INVALID_FLYWAY_SRV = """
{pre} one or more flyway action specifications in the provided target specification have invalid values for the destination server(s).
""".format(pre=PRE_MSG)

INVALID_RSYNC_PARAMS = """
{pre} it failed to format one or more rsync action parameters in the provided target specification.
""".format(pre=PRE_MSG)

INVALID_RSYNC_SPEC = """
{pre} one or more rsync action specifications in the provided target specification do not define the required action parameters.
""".format(pre=PRE_MSG)

INVALID_RSYNC_SRV = """
{pre} one or more rsync action specifications in the provided target specification have invalid values for the destination server(s).
""".format(pre=PRE_MSG)

NO_ACTION_TYPE = """
{pre} one or more action specifications in the provided target specification do not define an action type.
""".format(pre=PRE_MSG)

NO_COLO_ARG = """
{pre} the "--colo" command-line argument was not specified.
""".format(pre=PRE_MSG)

NO_SUBTYPE = """
{pre} no subtype of "colo" was provided for dst_srv.
""".format(pre=PRE_MSG)

NO_TARGETS_KEY = """
{pre} the selected configuration file does not contain the required "targets" key.
""".format(pre=PRE_MSG)

CONFIG_DIR_DOESNT_EXIST = """
{pre} the specified configuration directory does not exist on the local filesystem.
""".format(pre=PRE_MSG)

FLYWAY_DOESNT_EXIST = """
{pre} the specified flyway executable path does not exist on the local filesystem.
""".format(pre=PRE_MSG)

FLYWAY_CONFIG_DOESNT_EXIST = """
{pre} the specified flyway configuration file does not exist on the local filesystem.
""".format(pre=PRE_MSG)

RSYNC_DOESNT_EXIST = """
{pre} the specified rsync executable path does not exist on the local filesystem.
""".format(pre=PRE_MSG)

TARGET_DOESNT_EXIST = """
{pre} the provided target specification does not exist within the selected configuration file.
""".format(pre=PRE_MSG)

TARGETS_NOT_DICT = """
{pre} the "targets" key in selected configuration file does not correspond to a dictionary of target specifications.
""".format(pre=PRE_MSG)

UNABLE_TO_CMD = """
{pre} it encountered an issue while trying to execute one of the command action specifications within the provided target specifications.
""".format(pre=PRE_MSG)

UNABLE_TO_FLYWAY = """
{pre} it encountered an issue while trying to execute one of the flyway action specifications within the provided target specifications.
""".format(pre=PRE_MSG)

UNABLE_TO_RSYNC = """
{pre} it encountered an issue while trying to execute one of the rsync action specifications within the provided target specifications.
""".format(pre=PRE_MSG)

UNKNOWN_HOSTNAME = """
{pre} it encountered an exception while trying to discern the hostname of the machine. Good luck finding it.
""".format(pre=PRE_MSG)

WRONG_SUBTYPE = """
{pre} the specified colo subtype does not exist in the corresponding colo.
""".format(pre=PRE_MSG)

