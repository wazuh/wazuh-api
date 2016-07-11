#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh.utils import execute, cut_array, sort_array, search_array
from wazuh.agent import Agent
from wazuh.database import Connection
from wazuh import common
from glob import glob

def run(agent_id=None, all_agents=False):
    if all_agents:
        return execute([common.agent_control, '-j', '-r', '-a'])
    else:
        return execute([common.agent_control, '-j', '-r', '-u', agent_id])

def clear(agent_id=None, all_agents=False):
    '''Clear the database for one agent or for every agent
       all_agents must be an integer: 1 (true) or 0 (false)'''

    # Clear DB
    if int(all_agents):
        db_agents = glob('{0}/*-*.db'.format(common.database_path_agents))
    else:
        db_agents = glob('{0}/{1}-*.db'.format(common.database_path_agents, agent_id))

    if not db_agents:
        raise WazuhException(1600)

    for db_agent in db_agents:
        conn = Connection(db_agent)
        conn.begin()
        try:
            conn.execute('DELETE FROM fim_event')
            conn.execute('DELETE FROM fim_file')
        except Exception as exception:
            raise exception
        finally:
            conn.commit()
            conn.vacuum()

    # Clear OSSEC info
    if int(all_agents):
        retval = execute([common.syscheck_control, '-j', '-u', 'all'])
    else:
        retval = execute([common.syscheck_control, '-j', '-u', agent_id])

    return retval

def last_scan(agent_id):
    agent = Agent(agent_id)
    agent.get()
    data = {'syscheckTime': agent.syscheckTime, 'syscheckEndTime': agent.syscheckEndTime};

    return data

def files(agent_id=None, event=None, filename=None, filetype='file', summary=False, offset=0, limit=common.database_limit, sort=None, search=None):
    '''Return a list of files from the database that match the filters'''

    # Connection
    db_agent = glob('{0}/{1}-*.db'.format(common.database_path_agents, agent_id))
    if not db_agent:
        raise WazuhException(1600)
    else:
        db_agent = db_agent[0]

    conn = Connection(db_agent)

    fields = {'date': 'date', 'modificationDate': 'mtime', 'file': 'path', 'size': 'size', 'user': 'uname', 'group': 'gname'}

    # Query
    query = "SELECT {0} FROM fim_event, fim_file WHERE fim_event.id_file = fim_file.id AND fim_file.type = :filetype"
    request = {'filetype': filetype}

    if event:
        query += ' AND fim_event.type = :event'
        request['event'] = event

    if filename:
        query += ' AND path = :filename'
        request['filename'] = filename

    if search:
        query += " AND NOT" if bool(search['negation']) else ' AND'
        query += " (" + " OR ".join(x + ' LIKE :search' for x in ('path', "datetime(date, 'unixepoch')", 'size', 'md5', 'sha1', 'uname', 'gname', 'inode')) + ")"
        request['search'] = '%{0}%'.format(search['value'])

    # Total items
    if summary:
        query += ' group by path'
        conn.execute("SELECT COUNT(*) FROM ({0}) AS TEMP".format(query.format("max(datetime(date, 'unixepoch'))")), request)
    else:
        conn.execute(query.format('COUNT(*)'), request)

    data = {'totalItems': conn.fetch()[0]}

    # Sorting
    if sort:
        allowed_sort_fields = fields.keys()
        for sf in sort['fields']:
            if sf not in allowed_sort_fields:
                raise WazuhException(1403, 'Allowed sort fields: {0}. Field: {1}'.format(allowed_sort_fields, sf))

        query += ' ORDER BY ' + ','.join(['{0} {1}'.format(fields[i], sort['order']) for i in sort['fields']])
    else:
        query += ' ORDER BY date DESC'

    query += ' LIMIT :offset,:limit'
    request['offset'] = offset
    request['limit'] = limit

    if summary:
        select = ["max(datetime(date, 'unixepoch'))", "fim_event.type", "path"]
    else:
        select = ["datetime(date, 'unixepoch')", "fim_event.type", "path", "size", "perm", "uid", "gid", "md5", "sha1", "uname", "gname", "datetime(mtime, 'unixepoch')", "inode"]

    conn.execute(query.format(','.join(select)), request)

    data['items'] = []

    for tuple in conn:
        if summary:
            data['items'].append({'date': tuple[0], 'event': tuple[1], 'file': tuple[2]})
        else:
            data['items'].append({'date': tuple[0], 'event': tuple[1], 'file': tuple[2], 'size': tuple[3], 'perm': tuple[4], 'uid': tuple[5], 'gid': tuple[6], 'md5': tuple[7], 'sha1': tuple[8], 'user': tuple[9], 'group': tuple[10], 'modificationDate': tuple[11], 'inode': tuple[12]})

    return data
