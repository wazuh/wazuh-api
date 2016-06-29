#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh.utils import execute, cut_array
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
       all_agents must be boolean or integer: 1 (true) or 0 (false)'''

    conn = Connection()

    try:
        if int(all_agents):
            conn.execute('DELETE FROM pm_event')
            retval = execute([common.rootcheck_control, '-j', '-u', 'all'])
        else:
            conn.execute('DELETE FROM pm_event WHERE id_agent = ?', [agent_id])
            retval = execute([common.rootcheck_control, '-j', '-u', agent_id])
    except Exception as exception:
        raise exception
    finally:
        conn.vacuum()

    return retval

def print_db(agent_id=None, offset=0, limit=common.database_limit):
    '''Return a list of events from the database'''

    conn = Connection()
    query = """SELECT * FROM
        (SELECT 'outstanding' AS status, datetime(date_first, 'unixepoch') AS date_first, datetime(date_last, 'unixepoch') AS date_last, log, id_agent
            FROM pm_event AS t
            WHERE date_last > (SELECT date_last - 86400 FROM pm_event WHERE id_agent = t.id_agent AND log = 'Ending rootcheck scan.')
        UNION
        SELECT 'solved' AS status, datetime(date_first, 'unixepoch') AS date_first, datetime(date_last, 'unixepoch') AS date_last, log, id_agent
            FROM pm_event AS t
            WHERE date_last <= (SELECT date_last - 86400 FROM pm_event WHERE id_agent = t.id_agent AND log = 'Ending rootcheck scan.'))
        WHERE log NOT IN ('Starting rootcheck scan.', 'Ending rootcheck scan.', 'Starting syscheck scan.', 'Ending syscheck scan.')"""

    if (agent_id):
        query += ' AND id_agent = ?'
        data = [agent_id]
    else:
        data = []

    query += ' ORDER BY date_last DESC LIMIT ?,?'
    data += [offset, limit]
    conn.execute(query, data)
    data = []

    for tuple in conn:
        data.append({'status': tuple[0], 'oldDay': tuple[1], 'readDay': tuple[2], 'event': tuple[3]})

    return data

def last_scan(agent_id):
    agent = Agent(agent_id)
    agent.get()
    data = {'rootcheckTime': agent.rootcheckTime, 'rootcheckEndTime': agent.rootcheckEndTime};

    return data
