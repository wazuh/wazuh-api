#!/usr/bin/env bash

# Copyright (C) 2015-2016 Wazuh, Inc.All rights reserved.
# Wazuh.com
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Aux functions
print() {
    echo -e $1
}

error_and_exit() {
    echo "Error executing command: '$1'."
    echo 'Exiting.'
    exit 1
}

exec_cmd_bash() {
    bash -c "$1" || error_and_exit "$1"
}

exec_cmd() {
    eval $1 > /dev/null 2>&1 || error_and_exit "$1"
}

get_configuration_value () { # $1 setting
    cat "$API_PATH/configuration/config.js" | grep -P "config.$1\s*=\s*\"" | grep -P '".*"' -o | tr -d '"'
}

edit_configuration() { # $1 -> setting,  $2 -> value
    sed -i "s/^config.$1\s=.*/config.$1 = \"$2\";/g" "$API_PATH/configuration/config.js" || error_and_exit "sed (editing configuration)"
}

get_type_service() {
    if [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
        echo "systemctl"
    else
        echo "service"
    fi
}

get_node(){
    NODE_DIR=$(which nodejs 2> /dev/null)

    if [ "X$NODE_DIR" = "X" ]; then
        NODE_DIR=$(which node 2> /dev/null)

        if [ "X$NODE_DIR" = "X" ]; then
            echo "NodeJS binaries not found. Is NodeJS installed?"
            exit 1
        fi
    fi
    echo $NODE_DIR
}

check_program_installed() {
    hash $1 > /dev/null 2>&1
    if [ "$?" != "0" ]; then
        print "command $1 not found. is it installed?."
        exit 1
    fi
}
# END Aux functions

previous_checks() {
    # Test root permissions
    if [ "$EUID" -ne 0 ]; then
        print "Please run this script with root permissions.\nExiting."
        exit 1
    fi

    # Paths
    OSSEC_CONF="/etc/ossec-init.conf"
    DEF_OSSDIR="/var/ossec"

    if ! [ -f $OSSEC_CONF ]; then
        print "Can't find $OSSEC_CONF. Is OSSEC installed?.\nExiting."
        exit 1
    fi

    . $OSSEC_CONF

    if [ -z "$DIRECTORY" ]; then
        DIRECTORY=$DEF_OSSDIR
    fi

    serv_type=$(get_type_service)
    node_dir=$(get_node)
    API_PATH="${DIRECTORY}/api"


    # Dependencies
    check_program_installed "openssl"
}

change_port () {
    print ""
    read -p "TCP port [55000]: " port
    if [ "X${port}" == "X" ] || [ "X${port}" == "X55000" ]; then
        edit_configuration "port" "55000"
        print "Using TCP port 55000."
    else
        edit_configuration "port" $port
        print "Changing TCP port to $port."
    fi
}

change_https () {
    print ""
    read -p "Enable HTTPS and generate SSL certificate? [Y/n]: " https
    if [ "X${https,,}" == "X" ] || [ "X${https,,}" == "Xy" ]; then
        edit_configuration "https" "yes"

        print ""
        read -p "Step 1: Create key [Press Enter]" enter
        exec_cmd_bash "cd $API_PATH/configuration/ssl && openssl genrsa -des3 -out server.key 1024 && cp server.key server.key.org && openssl rsa -in server.key.org -out server.key"

        print ""
        read -p "Step 2: Create self-signed certificate [Press Enter]" enter
        exec_cmd_bash "cd $API_PATH/configuration/ssl && openssl req -new -key server.key -out server.csr"
        exec_cmd "cd $API_PATH/configuration/ssl && openssl x509 -req -days 2048 -in server.csr -signkey server.key -out server.crt"
        exec_cmd "cd $API_PATH/configuration/ssl && rm -f server.csr && rm -f server.key.org"

        exec_cmd "chmod 400 $API_PATH/configuration/ssl/server.*"
        print "\nKey: $API_PATH/configuration/ssl/server.key.\nCertificate: $API_PATH/configuration/ssl/server.crt\n"

        read -p "Continue with next section [Press Enter]" enter
    else
        edit_configuration "https" "no"
        print "Using HTTP (not secure)."
    fi
}

change_auth () {
    print ""
    read -p "Enable user authentication? [Y/n]: " auth
    if [ "X${auth,,}" == "X" ] || [ "X${auth,,}" == "Xy" ]; then
        auth="y"
        edit_configuration "basic_auth" "yes"
        read -p "API user: " user

        exec_cmd_bash "cd $API_PATH/configuration/auth && $node_dir htpasswd -c user $user"
    else
        auth="n"
        print "Disabling authentication (not secure)."
        edit_configuration "basic_auth" "no"
    fi
}

change_proxy () {
    print ""
    read -p "is the API running behind a proxy server? [y/N]: " proxy
    if [ "X${proxy,,}" == "Xy" ]; then
        print "API running behind proxy server."
        edit_configuration "BehindProxyServer" "yes"
    else
        edit_configuration "BehindProxyServer" "no"
    fi
}

main () {
    previous_checks

    print "### Wazuh API Configuration ###"

    change_port
    change_https
    change_auth
    change_proxy

    print "\nConfiguration changed."

    print "\nRestarting API."
    if [ $serv_type == "systemctl" ]; then
        exec_cmd "systemctl restart wazuh-api"
    else
        exec_cmd "service wazuh-api restart"
    fi

    print "\n### [Configuration changed] ###"
    exit 0
}

main
