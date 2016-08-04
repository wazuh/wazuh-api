#!/usr/bin/env bash

# Copyright (C) 2015-2016 Wazuh, Inc.All rights reserved.
# Wazuh.com
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Installer for Wazuh-API
# Wazuh Inc.
# Instructions:
#  - ./install_api.sh dependencies: List dependencies.
#  - ./install_api.sh dev: Install API from development branch.
#  - ./install_api.sh: Install API from release.


arg=$1

DOWNLOAD_PATH_RELEASE="https://github.com/wazuh/wazuh-API/archive/stable.zip"
DOWNLOAD_PATH_DEV="https://github.com/wazuh/wazuh-API/archive/development.zip"

print() {
    echo -e $1
}

error_and_exit() {
    echo "Error executing command: '$1'."
    echo 'Exiting.'
    exit 1
}

exec_cmd() {
    bash -c "$1" > /dev/null 2>&1 || error_and_exit "$1"
}

exec_cmd_no_exit() {
    bash -c "$1" > /dev/null 2>&1
}

exec_cmd_output() {
    bash -c "$1" || error_and_exit "$1"
}

exec_cmd_debug() {
    echo $1
    bash -c "$1"
}

check_arguments() {
    if [ "X${arg}" == "Xdependencies" ]; then
        required_packages
        exit 0
    else
        if [ "X${arg}" == "Xdev" ]; then
            DOWNLOAD_PATH=$DOWNLOAD_PATH_DEV
        else
            DOWNLOAD_PATH=$DOWNLOAD_PATH_RELEASE
        fi
    fi
}

previous_checks() {
    OSSEC_CONF="/etc/ossec-init.conf"
    DEF_OSSDIR="/var/ossec"

    # Test root permissions
    if [ "$USER" != "root" ]; then
        print "Please run this script with root permissions.\nExiting."
        exit 1
    fi

    # Directory where OSSEC is installed
    if ! [ -f $OSSEC_CONF ]; then
        print "Can't find $OSSEC_CONF. Is OSSEC installed?.\nExiting."
        exit 1
    fi

    . $OSSEC_CONF

    if [ -z "$DIRECTORY" ]; then
        DIRECTORY=$DEF_OSSDIR
    fi

    API_PATH="${DIRECTORY}/api"

    exec_cmd_no_exit "python -c 'import wazuh'"
    RC=$?

    if [[ $RC != 0 ]]; then
        print "wazuh-framework not found. It should have been installed with ossec-wazuh.\nExiting."
        exit 1
    fi
}

required_packages() {
    print "\nDebian and Ubuntu based Linux distributions:"
    print "\tsudo apt-get install -y unzip wget apache2-utils"
    print "\tNodeJS and npm:"
    print "\t\tcurl -sL https://deb.nodesource.com/setup_4.x | sudo -E bash -"
    print "\t\tsudo apt-get install -y nodejs"

    print "\nRed Hat, CentOS and Fedora:"
    print "\tyum install -y unzip wget httpd-tools"
    print "\tNodeJS and npm:"
    print "\t\tcurl --silent --location https://rpm.nodesource.com/setup_4.x | bash -"
    print "\t\tsudo yum -y install nodejs"
}

setup_api() {
    # Download API
    print "Downloading API from $DOWNLOAD_PATH"
    exec_cmd "wget $DOWNLOAD_PATH -O /tmp/wazuh-API.zip"
    exec_cmd "unzip -o /tmp/wazuh-API.zip -d /tmp/wazuh-API"
    exec_cmd "rm /tmp/wazuh-API.zip"

    # Install API
    if [ -d $API_PATH ]; then
        while true; do
            read -p "Wazuh-API is installed. Do you want to update it? [y/n]: " yn
            case $yn in
                [Yy] ) update="yes"; break;;
                [Nn] ) break;;
            esac
        done
    fi

    if [ "X${update}" == "Xyes" ]; then
        print "Updating API at '$API_PATH'."
        exec_cmd "cp -r $API_PATH/configuration $DIRECTORY/api_config_backup"
        e_msg="updated"
    else
        print "Installing API at '$API_PATH'."
        e_msg="installed"
    fi

    if [ -d $API_PATH ]; then
        exec_cmd "rm -r $API_PATH"
    fi

    exec_cmd "mkdir $API_PATH"
    exec_cmd "cp -r /tmp/wazuh-API/*/* $API_PATH"

    if [ "X${update}" == "Xyes" ]; then
        exec_cmd "rm -r $API_PATH/configuration"
        exec_cmd "mv $DIRECTORY/api_config_backup $API_PATH/configuration"
    fi

    exec_cmd "rm -r /tmp/wazuh-API"

    print "Installing NodeJS modules."
    exec_cmd "cd $API_PATH && npm install"

    if [ "X${DIRECTORY}" != "X/var/ossec" ]; then
        repl="\\\/"
        escaped_ossec_path=`echo "$DIRECTORY" | sed -e "s#\/#$repl#g"`
        # config.js: config.ossec_path
        exec_cmd "sed -i 's/^config.ossec_path\s=.*/config.ossec_path = \"$escaped_ossec_path\";/g' $API_PATH/configuration/config.js"
    fi

    print "Installing API as service."
    exec_cmd_output "$API_PATH/scripts/install_daemon.sh"

    print "API $e_msg."
}

configure_api() {
    print ""
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
        exec_cmd "sed -i 's/^config.port\s=.*/config.port = $port;/g' $API_PATH/configuration/config.js"
        print ""

        read -p "Use HTTPS? [Y/n]: " https
        if [ "X${https,,}" == "X" ] || [ "X${https,,}" == "Xy" ]; then
            protocol="https"
            exec_cmd "sed -i 's/^config.https\s=.*/config.https = \"yes\";/g' $API_PATH/configuration/config.js"

            read -p "Do you want to use out-of-the-box certificates? [y/N]: " certs
            if [ "X${certs,,}" == "X" ] || [ "X${certs,,}" == "Xn" ]; then
                print ""
                read -p "Create key [ENTER]" enter
                exec_cmd_output "cd $API_PATH/configuration/ssl && openssl genrsa -des3 -out server.key 1024 && cp server.key server.key.org && openssl rsa -in server.key.org -out server.key"

                print ""
                read -p "Create certificate signing request (CSR) [ENTER]" enter
                exec_cmd_output "cd $API_PATH/configuration/ssl && openssl req -new -key server.key -out server.csr"

                print ""
                read -p "Create self-signed certificate [ENTER]" enter
                exec_cmd "cd $API_PATH/configuration/ssl && openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt"

                exec_cmd "cd $API_PATH/configuration/ssl && rm server.csr && rm server.key.org"

                print "\nKey: $API_PATH/configuration/ssl/server.key.\nCertificate: $API_PATH/configuration/ssl/server.crt\n"
                read -p "Continue with the next section [ENTER]" enter

            else
                print "Using out-of-the-box certificates (not secure)."
            fi

        else
            protocol="http"
            print "Using HTTP (not secure)."
            exec_cmd "sed -i 's/^config.https\s=.*/config.https = \"no\";/g' $API_PATH/configuration/config.js"
        fi
        print ""

        auth="y"
        read -p "Use user authentication? [Y/n]: " auth
        if [ "X${auth,,}" == "X" ] || [ "X${auth,,}" == "Xy" ]; then
            auth="y"
            exec_cmd "sed -i 's/^config.basic_auth\s=.*/config.basic_auth = \"yes\";/g' $API_PATH/configuration/config.js"

            read -p "Do you want to use out-of-the-box users? [y/N]: " users
            if [ "X${users,,}" == "X" ] || [ "X${users,,}" == "Xn" ]; then
                read -p "API user: " user
                exec_cmd_output "cd $API_PATH/configuration/auth && htpasswd -c htpasswd $user"
            else
                print "Using out-of-the-box user/password (not secure)."
            fi
        else
            auth="n"
            print "Disabling authentication (not secure)."
            exec_cmd "sed -i 's/^config.basic_auth\s=.*/config.basic_auth = \"no\";/g' $API_PATH/configuration/config.js"
        fi
        print ""

        read -p "is the API running behind a proxy server? [y/N]: " proxy
        if [ "X${proxy,,}" == "Xy" ]; then
            print "API running behind proxy server."
            exec_cmd "sed -i 's/^config.BehindProxyServer\s=.*/config.BehindProxyServer = \"yes\";/g' $API_PATH/configuration/config.js"
        else
            exec_cmd "sed -i 's/^config.BehindProxyServer\s=.*/config.BehindProxyServer = \"no\";/g' $API_PATH/configuration/config.js"
        fi

        print "\nConfiguration is done."

        print "\nRestarting API."
        systemctl restart wazuh-api
    else
        protocol="https"
        auth="y"
        port="55000"
    fi

    print "\nYou can manually change the configuration by editing the file $API_PATH/config.js."

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
    print ""
}

main() {
    print "### Wazuh-API ###"
    check_arguments
    previous_checks
    setup_api
    if [ "X${update}" != "Xyes" ]; then
        configure_api
    fi
    print "### [API $e_msg successfully] ###\n"
    exit 0
}

# Main
main
