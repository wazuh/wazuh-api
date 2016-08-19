#!/usr/bin/env bash

# Copyright (C) 2015-2016 Wazuh, Inc.All rights reserved.
# Wazuh.com
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Installer for Wazuh Framework
# Wazuh Inc.
# Instructions:
#  - ./install_framework.sh dependencies: List dependencies.
#  - ./install_framework.sh local: Install framework


arg=$1

DOWNLOAD_PATH_RELEASE="https://github.com/wazuh/wazuh-framework/archive/master.zip"  # stable
DOWNLOAD_PATH_DEV="https://github.com/wazuh/wazuh-framework/archive/master.zip"      # development

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

exec_cmd_no_exit() {
    $1 > /dev/null 2>&1
}

exec_cmd_output() {
    $1 || error_and_exit "$1"
}

exec_cmd_debug() {
    echo $1
    $1
}

check_arguments() {
    if [ "X${arg}" == "Xdependencies" ]; then
        required_packages
        exit 0
    else
        if [ "X${arg}" == "Xdev" ]; then
            DOWNLOAD_PATH=$DOWNLOAD_PATH_DEV
        elif [ "X${arg}" == "Xlocal" ]; then
            SOURCE_PATH=`pwd`
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

    FRAMEWORK_PATH="${DIRECTORY}/framework"
}

required_packages() {
    print "\npip:"
    print "\tDebian and Ubuntu based Linux distributions: sudo apt-get install python-pip"
    print "\tRed Hat, CentOS and Fedora: sudo yum install python-pip"

    print "\nvirtualenv:"
    print "\tpip install virtualenv"
    print "\n"
}

setup_framework() {
    if [ "X${arg}" != "Xlocal" ]; then
        print "Only local installation supported: ./install_framework.sh local"
        exit
    else
        print "Wazuh-framework [$SOURCE_PATH]\n"
    fi

    if [ -d $FRAMEWORK_PATH ]; then
        while true; do
            read -p "Wazuh-Framework is installed. Do you want to update it? [y/n]: " yn
            case $yn in
                [Yy] ) update="yes"; break;;
                [Nn] ) update="no"; break;;
            esac
        done
    fi

    if [ "X${update}" == "Xyes" ]; then
        print "Updating ..."
        exec_cmd "cd $FRAMEWORK_PATH"
        e_msg="updated"
        exec_cmd "source env/bin/activate"
        exec_cmd_output "pip install $SOURCE_PATH --upgrade"
        print "\n"
    else
        print "Installing Framework at '$FRAMEWORK_PATH'."
        exec_cmd "mkdir -p $FRAMEWORK_PATH"
        exec_cmd "cd $FRAMEWORK_PATH"
        if [ "X${update}" == "Xno" ]; then
            exec_cmd "rm -rf $FRAMEWORK_PATH/env"
        fi
        exec_cmd "virtualenv env"
        exec_cmd "source env/bin/activate"
        exec_cmd_output "pip install $SOURCE_PATH"
        print "\n"
        e_msg="installed"
    fi

    if [ "X${arg}" != "Xlocal" ]; then
        echo "ToDo: Remove tmp..."
        #exec_cmd "rm -r /tmp/wazuh-framework"
    fi

    print "Wazuh framework $e_msg."
}

main() {
    print "### Wazuh-Framework ###"
    check_arguments
    previous_checks
    setup_framework

    print "\nRemember to activate the virtual environment to use the framework:"
    print "\tsource /var/ossec/framework/env/bin/activate"
    print "And if you want to go back to the real world:"
    print "\tdeactivate"

    print "\n### [Wazuh-Framework $e_msg successfully] ###\n"
    exit 0
}

# Main
main
