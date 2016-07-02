#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh.utils import execute, cut_array, sort_array, search_array
from wazuh.agent import Agent
from wazuh.database import Connection
from wazuh import common

def run(agent_id=None, all_agents=False):
    if all_agents:
        return execute([common.agent_control, '-j', '-r', '-a'])
    else:
        return execute([common.agent_control, '-j', '-r', '-u', agent_id])

def clear(agent_id=None, all_agents=False):
    '''Clear the database for one agent or for every agent
       all_agents must be an integer: 1 (true) or 0 (false)'''

    conn = Connection()
    conn.begin()

    try:
        if int(all_agents):
            conn.execute('DELETE FROM fim_event')
            conn.execute('DELETE FROM fim_file')
            retval = execute([common.syscheck_control, '-j', '-u', 'all'])
        else:
            conn.execute('DELETE FROM fim_event WHERE id_file IN (SELECT id FROM fim_file WHERE id_agent = ?)', [agent_id])
            conn.execute('DELETE FROM fim_file WHERE id_agent = ?', [agent_id])
            retval = execute([common.syscheck_control, '-j', '-u', agent_id])
    except Exception as exception:
        raise exception
    finally:
        conn.commit()
        conn.vacuum()

    return retval

def last_scan(agent_id):
    agent = Agent(agent_id)
    agent.get()
    data = {'syscheckTime': agent.syscheckTime, 'syscheckEndTime': agent.syscheckEndTime};

    return data

def files(agent_id=None, event=None, filename=None, filetype='file', offset=0, limit=common.database_limit, sort=None, search=None):
    '''Return a list of files from the database that match the filters'''

    conn = Connection()
    fields = {'agentID': 'id_agent', 'date': 'date', 'file': 'path', 'size': 'size'}

    query = "SELECT {0} FROM fim_event, fim_file WHERE id_file = fim_file.id AND type = :filetype"
    request = {'filetype': filetype}

    if agent_id:
        query += ' AND id_agent = :agentid'
        request['agentid'] = agent_id

    if event:
        query += ' AND event = :event'
        request['event'] = event

    if filename:
        query += ' AND path = :filename'
        data['filename'] = filename

    if search:
        query += " AND NOT" if bool(search['negation']) else ' AND'
        query += " (" + " OR ".join(x + ' LIKE :search' for x in ('path', "datetime(date, 'unixepoch')", 'size', 'md5', 'sha1')) + ")"
        request['search'] = '%{0}%'.format(search['value'])

    # Total items

    conn.execute(query.format('COUNT(*)'), request)
    data = {'totalItems': conn.fetch()[0]}

    # Sorting

    if sort:
        query += ' ORDER BY ' + ','.join(['{0} {1}'.format(fields[i], sort['order']) for i in sort['fields']])
    else:
        query += ' ORDER BY date DESC'

    query += ' LIMIT :offset,:limit'
    request['offset'] = offset
    request['limit'] = limit
    conn.execute(query.format("datetime(date, 'unixepoch'), id_agent, event, path, size, perm, uid, gid, md5, sha1"), request)

    data['items'] = []

    for tuple in conn:
        data['items'].append({'date': tuple[0], 'agentID': tuple[1], 'event': tuple[2], 'file': tuple[3], 'size': tuple[4], 'perm': tuple[5], 'uid': tuple[6], 'gid': tuple[7], 'md5': tuple[8], 'sha1': tuple[9]})

    return data

def files_total(agent_id=None, event=None, filename=None, filetype='file'):
    '''Return the number of files in the database that match the filter'''

    conn = Connection()
    query = 'SELECT COUNT(*) FROM fim_event, fim_file WHERE id_file = fim_file.id AND type = ?'
    data = [filetype]

    if agent_id:
        query += ' AND id_agent = ?'
        data.append(agent_id)

    if event:
        query += ' AND event = ?'
        data.append(event)

    if filename:
        query += ' AND path = ?'
        data.append(filename)

    conn.execute(query, data)
    return conn.fetch()[0]

def files_changed(agent_id, filename=None, filetype='file', offset=0, limit=0, sort=None, search=None):
    cmd = [common.syscheck_control, '-j', '-i', agent_id]
    if filename:
        cmd.extend(['-f', filename])
    data = execute(cmd)

    if search:
        data = search_array(data, search['value'], search['negation'])

    if sort:
        data = sort_array(data, sort['fields'], sort['order'])
    else:
        data = sort_array(data, ['date', 'file'], 'asc')

    return {'items': cut_array(data, offset, limit), 'totalItems': len(data)}

def files_changed_total(agent_id, filename=None):
    return files_changed(agent_id, filename)['totalItems']

def registry_changed(agent_id, filename=None, offset=0, limit=0, sort=None, search=None):
    cmd = [common.syscheck_control, '-j', '-r', '-i', agent_id]
    if filename:
        cmd.extend(['-f', filename])
    data = execute(cmd)

    if search:
        data = search_array(data, search['value'], search['negation'])

    if sort:
        data = sort_array(data, sort['fields'], sort['order'])
    else:
        data = sort_array(data, ['date', 'file'], 'asc')

    return {'items': cut_array(data, offset, limit), 'totalItems': len(data)}

def registry_changed_total(agent_id, filename=None):
    return registry_changed(agent_id, filename)['totalItems']
