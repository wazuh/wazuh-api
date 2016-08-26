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

check_program_installed() {
    hash $1 > /dev/null 2>&1
    if [ "$?" != "0" ]; then
        print "command $1 not found. is it installed?."
        if [ "$1" == "htpasswd" ]; then
            print "\nDebian and Ubuntu based Linux distributions: sudo apt-get install -y apache2-utils"
            print "\nRed Hat, CentOS and Fedora: sudo yum install -y httpd-tools"
        fi
        exit 1
    fi
}
# END Aux functions

previous_checks() {
    # Test root permissions
    if [ "$USER" != "root" ]; then
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

    API_PATH="${DIRECTORY}/api"


    # Dependencies
    check_program_installed "openssl"
    check_program_installed "htpasswd"
}

change_port () {
    print ""
    read -p "TCP port [55000]: " port
    if [ "X${port}" == "X" ] || [ "X${port}" == "X55000" ]; then
        print "Using TCP port 55000."
    else
        print "Changing TCP port to $port."
    fi

    edit_configuration "port" $port
}

change_https () {
    print ""
    read -p "Enable HTTPS? [Y/n]: " https
    if [ "X${https,,}" == "X" ] || [ "X${https,,}" == "Xy" ]; then
        edit_configuration "https" "yes"

        read -p "Generate private key and certificate [ENTER]" enter

        print ""
        read -p "Create key [ENTER]" enter
        exec_cmd_bash "cd $API_PATH/configuration/ssl && openssl genrsa -des3 -out server.key 1024 && cp server.key server.key.org && openssl rsa -in server.key.org -out server.key"

        print ""
        read -p "Create certificate signing request (CSR) [ENTER]" enter
        exec_cmd_bash "cd $API_PATH/configuration/ssl && openssl req -new -key server.key -out server.csr"

        print ""
        read -p "Create self-signed certificate [ENTER]" enter
        exec_cmd "cd $API_PATH/configuration/ssl && openssl x509 -req -days 2048 -in server.csr -signkey server.key -out server.crt"
        exec_cmd "cd $API_PATH/configuration/ssl && rm -f server.csr && rm -f server.key.org"

        print "\nKey: $API_PATH/configuration/ssl/server.key.\nCertificate: $API_PATH/configuration/ssl/server.crt\n"
        read -p "Continue with the next section [ENTER]" enter
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
        read -p "Create user and password [ENTER]" enter
        read -p "API user: " user
        exec_cmd_bash "cd $API_PATH/configuration/auth && htpasswd -c htpasswd $user"
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

    print "### Wazuh-API Configuration ###"

    change_port
    change_https
    change_auth
    change_proxy

    print "\nConfiguration changed."

    print "\nRestarting API."
    if [ "$serv_type" == "systemctl" ]; then
        exec_cmd "systemctl restart wazuh-api"
    else
        exec_cmd "service wazuh-api restart"
    fi

    print "\n### [Configuration changed] ###"
    exit 0
}

main
