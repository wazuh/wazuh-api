#!/usr/bin/env python
###
#  Copyright (C) 2015-2016 Wazuh, Inc.All rights reserved.
#  Wazuh.com
#
#  This program is a free software; you can redistribute it
#  and/or modify it under the terms of the GNU General Public
#  License (version 2) as published by the FSF - Free Software
#  Foundation.
###

import sys
import json

try:
    from wazuh import Wazuh
    from wazuh.agent import Agent
except Exception as e:
    print("No module 'wazuh' found.")
    sys.exit()

if __name__ == "__main__":

    # Creating wazuh object
    # It is possible to specify the ossec path (path argument) or get /etc/ossec-init.conf (get_init argument)
    print("\nWazuh:")
    myWazuh = Wazuh(get_init=True)
    print(myWazuh)

    print("\nAgents:")
    agents = Agent.get_agents_overview(status="all")
    print(json.dumps(agents, indent=4, sort_keys=True))

    print("\nAdding 'WazuhFrameworkTest':")
    agent = Agent()
    agent_id = agent.add("WazuhFrameworkTest", "Any")
    print("\nAgent added with ID: {0}".format(agent_id))
    print("\nAgent key: {0}".format(agent.get_key()))
    agent.get()
    print("\nAgent info:")
    print(json.dumps(agent.to_dict(), indent=4, sort_keys=True))
