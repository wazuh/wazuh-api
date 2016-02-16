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
 
exports.get_filter = function (query, allow_fields, max_query){
    var bad_field = false;
    var keys = Object.keys(query);
    
    if (keys.length == 0)
        return null;
    else if (keys.length <= max_query){
        var key_ok;
        var key;
        for (var k = 0, length = keys.length; k < length; k++){
            key =  keys[k];
            key_ok = false;
            for(var i=0;i<allow_fields.length;i++){
                if (key == allow_fields[i]){
                    key_ok = true;
                    break;
                }
            }
            if (!key_ok){
                bad_field = true;
                break;
            }
        }
    }
    
    if (bad_field)
        return "bad_field";
    else
        return query;
}
