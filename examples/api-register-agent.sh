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
GET_ID=$(curl -s -u $USER:"$PASSWORD" -k -X POST -d 'name='$AGENT_NAME $PROTOCOL://$API_IP:$API_PORT/agents)
ERROR=$(echo $GET_ID | sed -rn 's/.*"error":(.+)\,.*/\1/p')

if [ ! "$ERROR" = "0" ]; then
  echo $GET_ID | sed -rn 's/.*"message":"(.+)".*/\1/p'
  exit 1
fi

AGENT_ID=$(echo $GET_ID | sed -rn 's/.*"data":"(.+)".*/\1/p')

echo "Agent '$AGENT_NAME' with ID '$AGENT_ID' added."

# Getting agent key from Manager
echo ""
echo "Getting agent key:"
echo "curl -s -u $USER:**** -k -X GET $PROTOCOL://$API_IP:$API_PORT/agents/$AGENT_ID/key"
GET_KEY=$(curl -s -u $USER:"$PASSWORD" -k -X GET $PROTOCOL://$API_IP:$API_PORT/agents/$AGENT_ID/key)
ERROR=$(echo $GET_KEY | sed -rn 's/.*"error":(.+)\,.*/\1/p')

if [ ! "$ERROR" = "0" ]; then
  echo $GET_KEY | sed -rn 's/.*"message":"(.+)".*/\1/p'
  exit 1
fi

AGENT_KEY=$(echo $GET_KEY | sed -rn 's/.*"data":"(.+)".*/\1/p')

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
