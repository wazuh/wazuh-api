#!/usr/bin/env bash

# Copyright (C) 2015-2016 Wazuh, Inc.All rights reserved.
# Wazuh.com
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

echo "ToDo"
exit 1

required_packages() {
    print "\nDebian and Ubuntu based Linux distributions:"
    print "\tsudo apt-get install -y unzip wget apache2-utils python-pip"
    print "\tpip:"
    print "\t\tpip install virtualenv"
    print "\tNodeJS 4.x or newer:"
    print "\t\tcurl -sL https://deb.nodesource.com/setup_4.x | sudo -E bash -"
    print "\t\tsudo apt-get install -y nodejs"

    print "\nRed Hat, CentOS and Fedora:"
    print "\tsudo yum install -y unzip wget httpd-tools python-pip"
    print "\tpip:"
    print "\t\tpip install virtualenv"
    print "\tNodeJS 4.x or newer:"
    print "\t\tcurl --silent --location https://rpm.nodesource.com/setup_4.x | bash -"
    print "\t\tsudo yum -y install nodejs"
}

edit_configuration() { # $1 -> setting,  $2 -> value
    sed -i "s/^config.$1\s=.*/config.$1 = \"$2\";/g" "$API_PATH/configuration/config.js" || error_and_exit "sed (editing configuration)"
}

configure_api() {
    while true; do
        read -p "Wazuh-API is installed. Do you want to configure it? [y/n]: " yn
        case $yn in
            [Yy]* ) configure="yes"; break;;
            [Nn]* ) break;;
        esac
    done

    if [ "X${configure}" == "Xyes" ]; then
        print ""

        read -p "TCP port [55000]: " port
        if [ "X${port}" == "X" ] || [ "X${port}" == "X55000" ]; then
            print "Using default TCP port 55000."
            port="55000"
        else
            print "Changing TCP port to $port."
        fi

        edit_configuration "port" $port

        print ""

        read -p "Use HTTPS? [Y/n]: " https
        if [ "X${https,,}" == "X" ] || [ "X${https,,}" == "Xy" ]; then
            protocol="https"
            edit_configuration "https" "yes"

            read -p "Do you want to use out-of-the-box certificates? [y/N]: " certs
            if [ "X${certs,,}" == "X" ] || [ "X${certs,,}" == "Xn" ]; then
                print ""
                read -p "Create key [ENTER]" enter
                exec_cmd_bash "cd $API_PATH/configuration/ssl && openssl genrsa -des3 -out server.key 1024 && cp server.key server.key.org && openssl rsa -in server.key.org -out server.key"

                print ""
                read -p "Create certificate signing request (CSR) [ENTER]" enter
                exec_cmd_bash "cd $API_PATH/configuration/ssl && openssl req -new -key server.key -out server.csr"

                print ""
                read -p "Create self-signed certificate [ENTER]" enter
                exec_cmd "cd $API_PATH/configuration/ssl && openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt"

                exec_cmd "cd $API_PATH/configuration/ssl && rm -f server.csr && rm -f server.key.org"

                print "\nKey: $API_PATH/configuration/ssl/server.key.\nCertificate: $API_PATH/configuration/ssl/server.crt\n"
                read -p "Continue with the next section [ENTER]" enter

            else
                print "Using out-of-the-box certificates (not secure)."
            fi

        else
            protocol="http"
            print "Using HTTP (not secure)."
            edit_configuration "https" "no"
        fi
        print ""

        auth="y"
        read -p "Use user authentication? [Y/n]: " auth
        if [ "X${auth,,}" == "X" ] || [ "X${auth,,}" == "Xy" ]; then
            auth="y"
            edit_configuration "basic_auth" "yes"

            read -p "Do you want to use out-of-the-box users? [y/N]: " users
            if [ "X${users,,}" == "X" ] || [ "X${users,,}" == "Xn" ]; then
                read -p "API user: " user
                exec_cmd_bash "cd $API_PATH/configuration/auth && htpasswd -c htpasswd $user"
            else
                print "Using out-of-the-box user/password (not secure)."
            fi
        else
            auth="n"
            print "Disabling authentication (not secure)."
            edit_configuration "basic_auth" "no"
        fi
        print ""

        read -p "is the API running behind a proxy server? [y/N]: " proxy
        if [ "X${proxy,,}" == "Xy" ]; then
            print "API running behind proxy server."
            edit_configuration "BehindProxyServer" "yes"
        else
            edit_configuration "BehindProxyServer" "no"
        fi

        print "\nConfiguration is done."

        print "\nRestarting API."
        if [ $serv_type == "systemctl" ]; then
            exec_cmd "systemctl restart wazuh-api"
        else
            exec_cmd "service wazuh-api restart"
        fi
    else
        protocol="https"
        auth="y"
        port="55000"
    fi

    print "\nYou can manually change the configuration by editing the file $API_PATH/configuration/config.js."

    print "\n\nAPI URL: $protocol://localhost:$port/"
    if [ "X${auth,,}" == "Xy" ]; then
        if [ "X${user,,}" != "X" ]; then
            print "user: '$user'"
            print "pasword: '*****'"
        else
            print "user: 'foo'"
            print "pasword: 'bar'"
        fi
    else
        print "Authentication disabled (not secure)."
    fi

    if [ $serv_type == "systemctl" ]; then
        print "Service: systemctl status wazuh-api"
    else
        print "Service: service wazuh-api status"
    fi
    print ""
}
