#!/usr/bin/env bash

# Copyright (C) 2015-2016 Wazuh, Inc.All rights reserved.
# Wazuh.com
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.


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
    echo `node helpers/setup-passwords.js interactive`; 
else
    echo `node helpers/setup-passwords.js auto`; 
fi