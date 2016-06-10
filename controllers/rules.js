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

var express = require('express');
var res_h = require('../helpers/response_handler');
var filter = require('../helpers/filters');
var logger = require('../helpers/logger');
var validator = require('../helpers/input_validation');
var execute = require('../helpers/execute');
var config = require('../config.js');

var router = express.Router();
var wazuh_control = config.api_path + "/models/wazuh-control.py";

/********************************************/
/* GET
/********************************************/

// GET /rules
router.get('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /rules");
    var args = [];

    var filter0 = {'status':'alphanumeric_param', 'group': 'alphanumeric_param'};
    var filter1 = {'status':'alphanumeric_param', 'level': 'alphanumeric_param'};
    var filter2 = {'file':'alphanumeric_param'};
    var filter3 = {'status':'alphanumeric_param'};
    var filter4 = {'group':'alphanumeric_param'};
    var filter5 = {'level':'alphanumeric_param'};
    var filters = [filter0, filter1, filter2, filter3, filter4, filter5];

    var check_filter = filter.check(req.query, filters, res);
    if (check_filter[0] < 0)  // Filter with error
        return;
    else if (check_filter[0] == 1){ // Filter OK
        switch(check_filter[1]) {
            case 0: // status - group
                if (req.query.status == "all")
                    args = ["-f", "get_rules_with_group", "-a", req.query.group + ", enabled=False"];
                else
                    args = ["-f", "get_rules_with_group", "-a", req.query.group];
                break;
            case 1:  // status - level
                console.log("ToDo");
                break;
            case 2:  // file
                console.log("ToDo");
                break;
            case 3:  // status
                if (req.query.status == "all")
                    args = ["-f", "get_rules", "-a", "enabled=False" ];
                else
                    args = ["-f", "get_rules"];
                break;
            case 4:  // group
                args = ["-f", "get_rules_with_group", "-a", req.query.group];
                break;
            case 5:  // level
                console.log("ToDo");
                break;
        }
    }else { // No filter
        args = ["-f", "get_rules"];
    }

    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// GET /rules/groups
router.get('/groups', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /rules/groups");
    var args = ["-f", "get_groups"]
    execute.exec(wazuh_control, args, function (data) {res_h.send(res, data);});
})

// GET /rules/files
router.get('/files', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /rules/files");
    var args = ["-f", "get_rules_files"]
    execute.exec(wazuh_control, args, function (data) {res_h.send(res, data);});
})
/********************************************/
/* PUT
/********************************************/


/********************************************/
/* DELETE
/********************************************/


/********************************************/
/* POST
/********************************************/



module.exports = router;
