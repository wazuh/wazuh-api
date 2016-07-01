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

def previous_month(n=1):
    date = datetime.today().replace(day=1)  # First day of current month

    for i in range(0, int(n)):
        date = (date - timedelta(days=1)).replace(day=1)  # (first_day - 1) = previous month

    return date.replace(hour=00, minute=00, second=00, microsecond=00)

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

def sort_array(array, sort_by=None, order='asc', allowed_sort_fields=None):
    if not array:
        return array

    if order.lower() == 'desc':
        order_desc = True
    elif order.lower() == 'asc':
        order_desc = False
    else:
        raise WazuhException(1402)

    if allowed_sort_fields:
        for sort_field in sort_by:
            if sort_field not in allowed_sort_fields:
                raise WazuhException(1403, 'Allowed sort fields: {0}. Field: {1}'.format(allowed_sort_fields, sort_field))

    if sort_by:  # array should be a dictionary or a Class
        if type(array[0]) is dict:
            allowed_sort_fields = array[0].keys()
            for sort_field in sort_by:
                if sort_field not in allowed_sort_fields:
                    raise WazuhException(1403, 'Allowed sort fields: {0}. Field: {1}'.format(allowed_sort_fields, sort_field))

            return sorted(array, key = lambda o: tuple(o.get(a) for a in sort_by), reverse=order_desc)
        else:
            return sorted(array, key = lambda o: tuple(getattr(o,a) for a in sort_by), reverse=order_desc)
    else:
        return sorted(array, reverse=order_desc)

def get_values(o):
    strings = []

    try:
        obj = o.to_dict()  # Rule, Decoder, Agent...
    except:
        obj = o

    if type(obj) is list:
        for o in obj:
            strings.extend(get_values(o))
    elif type(obj) is dict:
        for key in obj:
            strings.extend(get_values(obj[key]))
    else:
        strings.append(str(obj).lower())

    return strings

def search_array(array, text, negation=False):
    found = []

    for item in array:

        values = get_values(item)

        #print("'{0}' in '{1}'?".format(text, values))

        if not negation:
            for v in values:
                if text.lower() in v:
                    found.append(item)
                    break
        else:
            not_in_values = True
            for v in values:
                if text.lower() in v:
                    not_in_values = False
                    break
            if not_in_values:
                found.append(item)

    return found
