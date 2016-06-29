#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh import common
from tempfile import mkstemp
from subprocess import call, CalledProcessError
from os import remove, close as close
from datetime import datetime, timedelta
import json

try:
    from subprocess import check_output
except ImportError:
    def check_output(arguments, stdin=None, stderr=None, shell=False):
        temp_f = mkstemp()
        returncode = call(arguments, stdin=stdin, stdout=temp_f[0], stderr=stderr, shell=shell)
        close(temp_f[0])
        file_o = open(temp_f[1], 'r')
        cmd_output = file_o.read()
        file_o.close()
        remove(temp_f[1])

        if returncode != 0:
            error_cmd = CalledProcessError(returncode, arguments[0])
            error_cmd.output = cmd_output
            raise error_cmd
        else:
            return cmd_output

def execute(command):
    try: output = check_output(command)
    except CalledProcessError as error: output = error.output
    except Exception as e:
        raise WazuhException(1002, "{0}: {1}".format(command, e))  # Error executing command

    try:
        output_json = json.loads(output)
    except Exception as e:
        raise WazuhException(1003, command)  # Command output not in json

    keys = output_json.keys() # error and (data or message)
    if 'error' not in keys or ('data' not in keys and 'message' not in keys):
        raise WazuhException(1004, command)  # Malformed command output

    if output_json['error'] != 0:
        raise WazuhException(output_json['error'], output_json['message'], True)
    else:
        return output_json['data']

def cut_array(array, offset, limit):
    if not array:
        return array

    offset = int(offset)
    limit = int(limit)

    if limit == 0:
        limit = common.database_limit

    if offset < 0 or offset >= len(array):
        raise WazuhException(1400)
    elif limit <= 0 or limit > common.database_limit:
        raise WazuhException(1401)
    else:
        return array[offset:offset+limit]

def previous_month(n=1):
    date = datetime.today().replace(day=1)  # First day of current month

    for i in range(0, int(n)):
        date = (date - timedelta(days=1)).replace(day=1)  # (first_day - 1) = previous month

    return date.replace(hour=00, minute=00, second=00, microsecond=00)
