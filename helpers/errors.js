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

var errors = {};

// 01 - 10 Internal Errors
errors['1'] = "Error executing internal command";
errors['2'] = "Command output not in JSON";
errors['3'] = "Internal error";

// 10 - 19 rootcheck_control
// 20 - 29 ossec-control
// 30 - 39 syscheck_control
// 40 - 49 agent_control
// 50 - 59 get_conf.py
// 60 - 69 stats.py
// 70 - 79 manage_agents
// 80 - 89 check_config.py


// 600 - 699 Requests
errors['600'] = "Param not valid. Integer expected";  // Integer
errors['601'] = "Param not valid. Valid characters: a-z, A-Z, 0-9, ., _, -,/,\\";  // Names
errors['603'] = "The requested URL was not found on this server";  // Default error
errors['604'] = "Filter error";  // Filter
errors['605'] = "Param not valid. Date format: YYYYMMDD";  // Date
errors['606'] = "Param not valid. IP invalid";  // IP
errors['607'] = "Invalid content-type. POST requests should be 'application/json' or 'application/x-www-form-urlencoded'";  // 

exports.description = function(n){
    if (n in errors)
        return errors[n];
    else
        return "Undefined error.";
}
