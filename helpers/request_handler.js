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

exports.get_filter = function (query, allow_fields){
    var bad_field = false;
    var filter = Object.keys(query);

    // Empty
    if (filter.length == 0)
        return null;

    // Filters
    if (filter.length <= allow_fields.length){
        for (var i = 0; i < filter.length; i++){
            var field_ok = false;

            // Fields
            for(var j=0; j<allow_fields.length; j++){
                if (filter[i] == allow_fields[j]){
                    field_ok = true;
                    break;
                }
            }

            if (!field_ok){
                bad_field = true;
                break;
            }
        }
    }
    else //Too much filters
        bad_field = true;

    if (bad_field)
        return "bad_field";
    else
        return query;
}
