#!/bin/bash

###
#  Shell script for registering agents automatically with the API
#  Copyright (C) 2017 Wazuh, Inc. All rights reserved.
#  Wazuh.com
#
#  This program is a free software; you can redistribute it
#  and/or modify it under the terms of the GNU General Public
#  License (version 2) as published by the FSF - Free Software
#  Foundation.
###


# Connection variables
API_IP="10.0.0.1"
API_PORT="55000"
PROTOCOL="http"
USER="foo"
PASSWORD="bar"

if [ "$#" = "0" ]; then
  AGENT_NAME=$(hostname)
else
  AGENT_NAME=$1
fi

# Adding agent and getting Id from manager
echo ""
echo "Adding agent:"
echo "curl -s -u $USER:**** -k -X POST -d 'name=$AGENT_NAME' $PROTOCOL://$API_IP:$API_PORT/agents"
API_RESULT=$(curl -s -u $USER:"$PASSWORD" -k -X POST -d 'name='$AGENT_NAME $PROTOCOL://$API_IP:$API_PORT/agents)
echo -e $API_RESULT | grep "\"error\":0" 2>&1

if [ "$?" != "0" ]; then
  echo -e $API_RESULT | sed -rn 's/.*"message":"(.+)".*/\1/p'
  exit 1
fi
# Get agent id and agent key 
AGENT_ID=$(echo $API_RESULT | cut -d':' -f 4 | cut -d ',' -f 1)
AGENT_KEY=$(echo $API_RESULT | cut -d':' -f 5 | cut -d '}' -f 1)

echo "Agent '$AGENT_NAME' with ID '$AGENT_ID' added."
echo "Key for agent '$AGENT_ID' received."

# Importing key
echo ""
echo "Importing authentication key:"
echo "y" | /var/ossec/bin/manage_agents -i $AGENT_KEY

# Restarting agent
echo ""
echo "Restarting:"
echo ""
/var/ossec/bin/ossec-control restart

exit 0