/**
 * API RESTful for OSSEC
 * Copyright (C) 2015-2016 Wazuh, Inc.All rights reserved.
 * Wazuh.com
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


var config = {};

config.ossec_path = "/var/ossec"
config.url = 'https://127.0.0.1:55000';
config.credentials = {'user':'foo', 'password':'bar'};

config.timeout = 30000;

module.exports = config;
