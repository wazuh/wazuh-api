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

def print_db(agent_id=None, offset=0, limit=common.database_limit, sort=None, search=None):
    '''Return a list of events from the database'''

    conn = Connection()
    request = {}
    fields = {'agentID': 'id_agent', 'status': 'status', 'event': 'log', 'oldDay': 'date_first', 'readDay': 'date_last'}

    partial = """SELECT {0} AS status, datetime(date_first, 'unixepoch') AS date_first, datetime(date_last, 'unixepoch') AS date_last, log, id_agent
        FROM pm_event AS t
        WHERE date_last {1} (SELECT date_last - 86400 FROM pm_event WHERE id_agent = t.id_agent AND log = 'Ending rootcheck scan.')"""

    query = "SELECT {0} FROM (" + partial.format("'outstanding'", '>') + ' UNION ' + partial.format("'solved'", '<=') + \
        ") WHERE log NOT IN ('Starting rootcheck scan.', 'Ending rootcheck scan.', 'Starting syscheck scan.', 'Ending syscheck scan.')"

    if agent_id:
        query += ' AND id_agent = :idagent'
        request['idagent'] = agent_id

    if search:
        query += " AND NOT" if bool(search['negation']) else ' AND'
        query += " (" + " OR ".join(x + ' LIKE :search' for x in ('status', 'date_first', 'date_last', 'log')) + ")"
        request['search'] = '%{0}%'.format(search['value'])

    # Total items

    conn.execute(query.format('COUNT(*)'), request)
    data = {'totalItems': conn.fetch()[0]}

    # Sorting

    if sort:
        query += ' ORDER BY ' + ','.join(['{0} {1}'.format(fields[i], sort['order']) for i in sort['fields']])
    else:
        query += ' ORDER BY date_last DESC'

    request['offset'] = offset
    request['limit'] = limit
    conn.execute(query.format('*') + ' LIMIT :offset,:limit', request)
    data['items'] = []

    for tuple in conn:
        data['items'].append({'status': tuple[0], 'oldDay': tuple[1], 'readDay': tuple[2], 'event': tuple[3], 'agentID': tuple[4]})

    return data

def last_scan(agent_id):
    agent = Agent(agent_id)
    agent.get()
    data = {'rootcheckTime': agent.rootcheckTime, 'rootcheckEndTime': agent.rootcheckEndTime};

    return data
