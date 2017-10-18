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
    API_PATH="${DIRECTORY}/api"

    # Dependencies
    check_program_installed "openssl"
}

change_port () {
    print ""
    port_preloaded=$(cat preloaded_vars.conf | sed -e '/^#/ d' | grep PORT)
    if [[ ! -z $port_preloaded ]]; then
        response=$(echo $port_preloaded | cut -d'=' -f 2 | tr -d '\r')
        print "Using $response port."
        edit_configuration "port" $response
    else
        read -p "TCP port [55000]: " port
        if [ "X${port}" == "X" ] || [ "X${port}" == "X55000" ]; then
            edit_configuration "port" "55000"
            print "Using TCP port 55000."
        else
            edit_configuration "port" $port
            print "Changing TCP port to $port."
        fi
    fi
}

change_https () {
    print ""
    https_preloaded=$(cat preloaded_vars.conf | sed -e '/^#/ d' | grep HTTPS)
    if [[ ! -z "$https_preloaded" ]]; then
        response=$(echo $https_preloaded | cut -d'=' -f 2 | tr -d '\r')
        case $response in
            [yY] ) edit_configuration "https" "yes";;
        esac
        country=$(cat preloaded_vars.conf | sed -e '/^#/ d' | grep C= | cut -d'=' -f 2 | tr -d '\"\r')
        state=$(cat preloaded_vars.conf | sed -e '/^#/ d' | grep ST= | cut -d'=' -f 2 | tr -d '\"\r')
        locality=$(cat preloaded_vars.conf | sed -e '/^#/ d' | grep L= | cut -d'=' -f 2 | tr -d '\"\r')
        org=$(cat preloaded_vars.conf | sed -e '/^#/ d' | grep O= | cut -d'=' -f 2 | tr -d '\"\r')
        orgunit=$(cat preloaded_vars.conf | sed -e '/^#/ d' | grep OU= | cut -d'=' -f 2 | tr -d '\"\r')
        commonname=$(cat preloaded_vars.conf | sed -e '/^#/ d' | grep CN= | cut -d'=' -f 2 | tr -d '\"\r')
        
        subject=$(echo "/C=$country/ST=$state/L=$locality/O=$org/O=$orgunit/CN=$commonname")
        actual_dir=$(pwd)

        # Step 1
        exec_cmd_bash "cd $API_PATH/configuration/ssl && openssl genrsa -des3 -out server.key -passout pass:foo 1024 && cp server.key server.key.org && openssl rsa -in server.key.org -out server.key -passin pass:foo"

        # Step 2
        exec_cmd_bash "cd $API_PATH/configuration/ssl && openssl req -new -key server.key -out server.csr -subj \"$subject\""
        exec_cmd "cd $API_PATH/configuration/ssl && openssl x509 -req -days 2048 -in server.csr -signkey server.key -out server.crt -passin pass:foo"
        exec_cmd "cd $API_PATH/configuration/ssl && rm -f server.csr && rm -f server.key.org"

        exec_cmd "chmod 600 $API_PATH/configuration/ssl/server.*"
        print "\nKey: $API_PATH/configuration/ssl/server.key.\nCertificate: $API_PATH/configuration/ssl/server.crt\n"

    else
        read -p "Enable HTTPS and generate SSL certificate? [Y/n/s]: " https
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

            exec_cmd "chmod 600 $API_PATH/configuration/ssl/server.*"
            print "\nKey: $API_PATH/configuration/ssl/server.key.\nCertificate: $API_PATH/configuration/ssl/server.crt\n"

            read -p "Continue with next section [Press Enter]" enter
        elif [ "X${https,,}" == "Xn" ]; then
            edit_configuration "https" "no"
            print "Using HTTP (not secure)."
        elif [ "X${https,,}" == "Xs" ]; then
            print "Skipping configuration."
        fi
    fi

    exec_cmd "cd $actual_dir"
}

change_auth () {
    print ""
    auth_preloaded=$(cat preloaded_vars.conf | sed -e '/^#/ d' | grep AUTH)
    if [[ ! -z "$auth_preloaded" ]]; then
        response=$(echo $auth_preloaded | cut -d'=' -f 2 | tr -d '\r')
        case $response in
            [yY] ) edit_configuration "basic_auth" "yes";;
        esac
        if [[ $response == 'y' || $response == 'Y' ]]; then
            user=$(cat preloaded_vars.conf | sed -e '/^#/ d' | grep USER= | cut -d'=' -f 2 | tr -d '\r')
            user_pass=$(cat preloaded_vars.conf | sed -e '/^#/ d' | grep PASS= | cut -d'=' -f 2 | tr -d '\r')

            exec_cmd_bash "cd $API_PATH/configuration/auth && $API_PATH/node_modules/htpasswd/bin/htpasswd -bc user $user $user_pass"
            exec_cmd_bash "cd $API_PATH/configuration/auth && $API_PATH/node_modules/htpasswd/bin/htpasswd -nb wazuh wazuh >> user"
        fi
    else
        read -p "Enable user authentication? [Y/n/s]: " auth
        if [ "X${auth,,}" == "X" ] || [ "X${auth,,}" == "Xy" ]; then
            auth="y"
            edit_configuration "basic_auth" "yes"
            read -p "API user: " user

            stty -echo
            printf "New password: "
            read user_pass
            printf "\nRe-type new password: "
            read user_pass_chk
            while [ ! $user_pass = $user_pass_chk ]; do
                 printf "\nPassword verification error."
                 printf "\nNew password: "
                 read user_pass
                 printf "\nRe-type new password: "
                 read user_pass_chk
            done
            printf "\n"
            stty echo

            exec_cmd_bash "cd $API_PATH/configuration/auth && $API_PATH/node_modules/htpasswd/bin/htpasswd -bc user $user $user_pass"
            exec_cmd_bash "cd $API_PATH/configuration/auth && $API_PATH/node_modules/htpasswd/bin/htpasswd -nb wazuh wazuh >> user"
        elif [ "X${auth,,}" == "Xn" ]; then
            auth="n"
            print "Disabling authentication (not secure)."
            edit_configuration "basic_auth" "no"
        elif [ "X${auth,,}" == "Xs" ]; then
            print "Skipping configuration."
        fi
    fi
}

change_proxy () {
    print ""
    proxy_preloaded=$(cat preloaded_vars.conf | sed -e '/^#/ d' | grep PROXY)
    if [[ ! -z "$proxy_preloaded" ]]; then
        response=$(echo $proxy_preloaded | cut -d'=' -f 2 | tr -d '\r')
        case $response in
            [yY] ) edit_configuration "BehindProxyServer" "yes";;
            [nN] ) edit_configuration "BehindProxyServer" "no";;
        esac
    else
        read -p "is the API running behind a proxy server? [y/N/s]: " proxy
        if [ "X${proxy,,}" == "Xy" ]; then
            print "API running behind proxy server."
            edit_configuration "BehindProxyServer" "yes"
        elif [ "X${proxy,,}" == "X" ] || [ "X${proxy,,}" == "Xn" ]; then
            print "API not running behind proxy server."
            edit_configuration "BehindProxyServer" "no"
        elif [ "X${proxy,,}" == "Xs" ]; then
            print "Skipping configuration."
        fi
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
