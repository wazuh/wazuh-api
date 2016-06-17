#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException

def cut_array(array, offset, limit):
    offset = int(offset)
    limit = int(limit)

    if offset == 0 and limit == 0:
        return array

    size = len(array)

    if offset < 0 or offset >= size:
        raise WazuhException(1400)
    elif limit <= 0 or limit > size:
        raise WazuhException(1401)
    else:
        return array[offset:offset+limit]
