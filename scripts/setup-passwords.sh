#!/usr/bin/env bash

# Copyright (C) 2015-2016 Wazuh, Inc.All rights reserved.
# Wazuh.com
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

BIN_DIR=$(which nodejs 2> /dev/null)

if [ "X$BIN_DIR" = "X" ]; then
    BIN_DIR=$(which node 2> /dev/null)

    if [ "X$BIN_DIR" = "X" ]; then
        echo "NodeJS binaries not found. Is NodeJS installed?"
        exit 1
    fi
fi


while true; do
    read -p "Set passwords automatically or interactively? [AUTO/interactive]: " mode
    case $mode in
        ("auto") auto="yes"; break;;
        ("AUTO") auto="yes"; break;;
        ("interactive")  auto="no"; break;;
        ("INTERACTIVE")  auto="no"; break;;
        ("")  auto="yes"; break;;
    esac
done


if [ "X${auto}" == "Xno" ]; then
    echo `$BIN_DIR helpers/setup-passwords.js interactive`; 
else
    echo `$BIN_DIR helpers/setup-passwords.js auto`; 
fi
