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

// 1 - 9 Internal Errors
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
errors['numbers'] = 600;
errors['601'] = "Param not valid. Valid characters: a-z, A-Z, 0-9, ., _, -";  // Names
errors['names'] = 601;
errors['603'] = "The requested URL was not found on this server";  // Default error
errors['604'] = "Filter error";  // Filter
errors['605'] = "Param not valid. Date format: YYYYMMDD";  // Date
errors['dates'] = 605;
errors['606'] = "Param not valid. IP invalid";  // IP
errors['ips'] = 606;  // IP
errors['607'] = "Invalid content-type. POST requests should be 'application/json' or 'application/x-www-form-urlencoded'";  //
errors['608'] = "Param not valid. Path invalid. Valid characters: a-z, A-Z, 0-9, ., _, -, :, /, \\";  // Paths
errors['paths'] = 608;
errors['609'] = "Param not valid. Valid characters: a-z, A-Z, 0-9, ., _, -, +";  // Alphanumeric params
errors['alphanumeric_param'] = 609;

exports.description = function(n){
    if (n in errors)
        return errors[n];
    else
        return "Undefined error.";
}
