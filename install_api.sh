#!/usr/bin/env bash

# Copyright (C) 2015-2016 Wazuh, Inc.All rights reserved.
# Wazuh.com
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Installer for Wazuh-API
# Wazuh Inc.
#
# Instructions:
#  List dependencies.
#    ./install_api.sh dependencies
#  Install last release (download last release)
#    ./install_api.sh
#  Install from current path
#    git clone https://github.com/wazuh/wazuh-API.git
#    cd wazuh-API
#    [git checkout <branch>]
#    Options:
#      ./install_api.sh local : Install API from current path
#      ./install_api.sh dev   : Install API from current path, development mode


# Configuration
API_SOURCES="/root"
DOWNLOAD_PATH_RELEASE="https://github.com/wazuh/wazuh-API/archive/stable.zip"

arg=$1

print() {
    echo -e $1
}

error_and_exit() {
    echo "Error executing command: '$1'."
    echo 'Exiting.'
    exit 1
}

exec_cmd() {
    $1 > /dev/null 2>&1 || error_and_exit "$1"
}

exec_cmd_bash() {
    bash -c "$1" || error_and_exit "$1"
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

check_arguments() {
    if [ "X${arg}" == "Xdependencies" ]; then
        required_packages
        exit 0
    else
        if [ "X${arg}" == "Xdev" ] || [ "X${arg}" == "Xlocal" ]; then
            API_SOURCES=`pwd`
        else
            DOWNLOAD_PATH=$DOWNLOAD_PATH_RELEASE
        fi
    fi
}

required_packages() {
    print "\nDebian and Ubuntu based Linux distributions:"
    print "\tsudo apt-get install -y unzip wget apache2-utils python-pip"
    print "\tpip:"
    print "\t\tpip install virtualenv"
    print "\tNodeJS and npm:"
    print "\t\tcurl -sL https://deb.nodesource.com/setup_4.x | sudo -E bash -"
    print "\t\tsudo apt-get install -y nodejs"

    print "\nRed Hat, CentOS and Fedora:"
    print "\tsudo yum install -y unzip wget httpd-tools python-pip"
    print "\tpip:"
    print "\t\tpip install virtualenv"
    print "\tNodeJS and npm:"
    print "\t\tcurl --silent --location https://rpm.nodesource.com/setup_4.x | bash -"
    print "\t\tsudo yum -y install nodejs"
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
    FRAMEWORK_PATH="${DIRECTORY}/framework"
    serv_type=$(get_type_service)
}

download_api () {
    if [ "X$DOWNLOAD_PATH" != "X" ]; then
        print "\nDownloading API from $DOWNLOAD_PATH"

        if [ -d "$API_SOURCES/wazuh-API" ]; then
            exec_cmd "rm -rf $API_SOURCES/wazuh-API"
        fi

        exec_cmd "wget $DOWNLOAD_PATH -O $API_SOURCES/wazuh-API.zip"
        exec_cmd "unzip -o $API_SOURCES/wazuh-API.zip -d $API_SOURCES/wazuh-API"
        exec_cmd "rm $API_SOURCES/wazuh-API.zip"

        API_SOURCES="$API_SOURCES/wazuh-API/wazuh-API-stable"
    else
        if [ "X${arg}" == "Xdev" ]; then
            print "\nInstalling Wazuh-API from current directory [$API_SOURCES] [DEV MODE]"
        else
            print "\nInstalling Wazuh-API from current directory [$API_SOURCES]"
        fi
    fi
}

install_framework() {
    FRAMEWORK_SOURCES="$API_SOURCES/framework"

    print "\nInstalling Framework in '$FRAMEWORK_PATH'."
    e_msg="installed"
    exec_cmd "mkdir -p $FRAMEWORK_PATH"
    exec_cmd "cd $FRAMEWORK_PATH"
    if [ -d "$FRAMEWORK_PATH/env" ]; then
        exec_cmd "rm -rf $FRAMEWORK_PATH/env"
    fi
    exec_cmd "virtualenv env"
    echo "----------------------------------------------------------------"
    if [ "X${arg}" == "Xdev" ]; then
        exec_cmd_bash "source env/bin/activate && pip install -e $FRAMEWORK_SOURCES && deactivate"
    else
        exec_cmd_bash "source env/bin/activate && pip install $FRAMEWORK_SOURCES && deactivate"
    fi
    echo "----------------------------------------------------------------"
    #fi

    # Check
    $FRAMEWORK_PATH/env/bin/python -c 'import wazuh'
    RC=$?
    if [[ $RC != 0 ]]; then
        print "Error installing Wazuh Framework.\nExiting."
        exit 1
    fi

    print "Wazuh Framework $e_msg."
}

setup_api() {
    # Check if API is installed
    if [ -d $API_PATH ]; then
        print ""
        while true; do
            read -p "Wazuh-API is installed. Do you want to update it? [y/n]: " yn
            case $yn in
                [Yy] ) update="yes"; break;;
                [Nn] ) update="no"; break;;
            esac
        done
    fi

    # Backup configuration and remove api directory
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

    # Install API
    if [ "X${arg}" == "Xdev" ]; then
        exec_cmd "ln -s $API_SOURCES $API_PATH"
    else
        exec_cmd "mkdir $API_PATH"
        exec_cmd "cp -r $API_SOURCES/* $API_PATH"
    fi

    # Restore configuration
    if [ "X${update}" == "Xyes" ]; then
        exec_cmd "rm -r $API_PATH/configuration"
        exec_cmd "mv $DIRECTORY/api_config_backup $API_PATH/configuration"
    fi

    print "Installing NodeJS modules."
    exec_cmd "cd $API_PATH && npm install --only=production"

    # Set OSSEC directory in API configuration
    if [ "X${DIRECTORY}" != "X/var/ossec" ]; then
        repl="\\\/"
        escaped_ossec_path=`echo "$DIRECTORY" | sed -e "s#\/#$repl#g"`
        edit_configuration "ossec_path" $escaped_ossec_path
    fi

    print "Installing API as service."
    echo "----------------------------------------------------------------"
    exec_cmd_bash "$API_PATH/scripts/install_daemon.sh"
    echo "----------------------------------------------------------------"

    print "API $e_msg.\n"
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

                exec_cmd "cd $API_PATH/configuration/ssl && rm server.csr && rm server.key.org"

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

main() {
    print "### Wazuh-API ###"
    check_arguments
    previous_checks
    download_api
    install_framework
    setup_api
    if [ "X${update}" != "Xyes" ]; then
        configure_api
    fi
    print "### [API $e_msg successfully] ###"
    exit 0
}

# Main
main
