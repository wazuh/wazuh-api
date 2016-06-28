#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh.utils import execute
from wazuh.agent import Agent
from wazuh.database import Connection
from wazuh import common

def run(agent_id):
    if agent_id == "ALL":
        return execute([common.agent_control, '-j', '-r', '-a'])
    else:
        return execute([common.agent_control, '-j', '-r', '-u', agent_id])

def clear(agent_id, all_agents=False):
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

def files(agent_id=None, event=None, filename=None, filetype='file', offset=0, limit=common.database_limit):
    '''Return a list of files from the database that match the filters'''

    conn = Connection()
    query = "SELECT datetime(date, 'unixepoch'), size, perm, uid, gid, md5, sha1 FROM fim_event, fim_file WHERE id_file = fim_file.id AND type = ?"
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

    query += ' ORDER BY date DESC LIMIT ?,?'
    data += [offset, limit]
    conn.execute(query, data)
    data = []

    for tuple in conn:
        data.append({'date': tuple[0], 'size': tuple[1], 'perm': tuple[2], 'uid': tuple[3], 'gid': tuple[4], 'md5': tuple[5], 'sha1': tuple[6]})

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

def files_changed(agent_id, filename=None, filetype='file'):
    cmd = [common.syscheck_control, '-j', '-i', agent_id]
    if filename:
        cmd.extend(['-f', filename])
    return execute(cmd)

def files_changed_total(agent_id, filename=None):
    files = Syscheck.files_changed(agent_id, filename)
    return len(files)

def registry_changed(agent_id, filename=None):
    cmd = [common.syscheck_control, '-j', '-r', '-i', agent_id]
    if filename:
        cmd.extend(['-f', filename])
    return execute(cmd)

def registry_changed_total(agent_id, filename=None):
    files = Syscheck.registry_changed(agent_id, filename)
    return len(files)
