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
errors['01'] = "Error executing internal command";
errors['02'] = "Command output not in JSON";

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
errors['601'] = "Param not valid. Valid characters: a-z, A-Z, 0-9, ., _, -";  // Names
errors['603'] = "No URI found. Bad HTTP verb?, typo?";  // Default error
errors['604'] = "Filter error";  // Filter

exports.description = function(n){
    if (n in errors)
        return errors[n];
    else
        return "Undefined error.";
}
