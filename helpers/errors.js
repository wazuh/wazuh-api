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

// 10 - 19 Rootcheck control
// 20 - 29 OSSEC Control
// 30 - 39 Syscheck control
// 40 - 49 Agent control
// 50 - 59 remove_agent.py

// 500 - 509 CMD
errors['500'] = "Error executing internal command";
errors['501'] = "Error: command output not in JSON";

// 600 - 699 Requests
errors['600'] = "Param not valid. Integer expected";  // Integer
errors['601'] = "Param not valid. Valid characters: a-z, A-Z, 0-9, ., _, -";  // Names
errors['603'] = "No URI found. Bad HTTP verb?, typo?";  // Names

exports.description = function(n){
    if (n in errors)
        return errors[n];
    else
        return "Undefined error.";
}
