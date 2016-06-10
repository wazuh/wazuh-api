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

var res_h = require('../helpers/response_handler');
var validator = require('../helpers/input_validation');
var errors = require('../helpers/errors');

/*
 * query = req.query
 * filters = [{'filter1_filed1':'type', 'filter1_field2':'type'},
 *            {'filter2_filed1':'type', 'filter2_field2':'type'},
 *           ]
 * res = response
 *
 * Return:
 *  [0,null]: There is no filter
 *  [Negative,null]: Error in filter. Also, it sends a response!*
 *  [1,id_filter]: matched filter.
*/
exports.check = function (query, filters, res){
    if (Object.keys(query).length ==  0)
        return [0,null];  // There is no filter

    var filter = null;
    var matched = false;
    for (var i = 0; i < filters.length; i++){
        filter = filters[i];
        matched = true;
        var query_aux = (JSON.parse(JSON.stringify(query)));  // Clone query

        for(var field in filter){
            if (field in query_aux)
                delete query_aux[field];
            else{
                matched = false;
                break;
            }
        }

        if (matched){
            // No extra fields
            if (Object.keys(query_aux).length != 0){
                res_h.bad_request("604", "Allowed filters: " + filters_to_string(filters), res);
                return [-1,null]; //Error: Allowed fields
            }
            break; // good filter -> go to check types
        }
        // else -> next filter
    }

    // No matched but there are filters
    if (!matched && Object.keys(query).length != 0){
        res_h.bad_request("604", "Allowed filters: " + filters_to_string(filters), res);
        return [-1,null]; //Error: Allowed fields
    }

    // Check types
    for(var key in filter){
        var field = key;
        var type = filter[key];

        if(!validator[type](query[field])){ // Bad type
            var erro_code = errors.description(type);
            res_h.bad_request(erro_code, " Field: " + field, res);
            return [-2, null];
        }
    }

    return [1,i]; // Filter OK
}

filters_to_string = function (filters){
    var output = "";
    for (var i = 0; i < filters.length; i++){
        filter = filters[i];
        output += "filter" + i + " : [";
        for(var field in filter)
            output += " " + field + " ";
        output += "]  ";
    }
    return output;
}
