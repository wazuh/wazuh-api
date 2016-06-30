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
 * query = req.query, req.params
 * filters = {'filter1':'type', 'filter2':'type'}
 * res = response
 *
 * Return:
 *  True, if matched filter
 *  False: Error in filter. Also, it sends a response!*
*/
exports.check = function (query, filters, res){
    var query_aux = (JSON.parse(JSON.stringify(query)));  // Clone query

    for(var field in filters){
        if (field in query){
            var type = filters[field]
            if(!validator[type](query[field])){ // Bad type
                var erro_code = errors.description(type);
                res_h.bad_request(erro_code, " Field: " + field, res);
                return false;
            }
            delete query_aux[field];
        }
    }

    // No extra fields
    if (Object.keys(query_aux).length != 0){
      res_h.bad_request("604", filters_to_string(filters), res);
      return false; //Error: Allowed fields
    }

    return true; // Filter OK
}

/*

 * filters = "-field1,field2"
 * Return:
 * sort_param = {"fields":["field1", "field1"], "order": "dsc"}
*/
exports.sort_param_to_json = function (sort_param){
    var sort = {"fields": [], "order": "asc"};

    var all_fields = sort_param;
    if (sort_param[0] == '-'){
        sort["order"] = "dsc";
        all_fields = sort_param.substring(1);
    }
    else if (sort_param[0] == ' '){  // +  is translated as a space
        sort["order"] = "asc";
        all_fields = sort_param.substring(1);
    }

    // Remove first character (- or +) and split by comma
    var fields = all_fields.split(',');

    if (fields[0].length != 0)
        for(var i = 0; i < fields.length; i++)
            sort["fields"].push(fields[i].trim());

    return sort
}

filters_to_string = function (filters){
    var output = "Allowed filters: [";
    for(var field in filters)
        output += " " + field + " ";
    output += "]  ";
    return output;
}
