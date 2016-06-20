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


var router = require('express').Router();

/********************************************/
/* GET
/********************************************/

// GET /rules
router.get('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /rules");
    var args = [];

    var filter0 = {'status':'alphanumeric_param', 'group': 'alphanumeric_param'};
    var filter1 = {'status':'alphanumeric_param', 'level': 'ranges'};
    var filter2 = {'status':'alphanumeric_param', 'file': 'alphanumeric_param'};
    var filter3 = {'status':'alphanumeric_param'};
    var filter4 = {'group':'alphanumeric_param'};
    var filter5 = {'level':'ranges'};
    var filter6 = {'file':'alphanumeric_param'};

    var filters = [filter0, filter1, filter2, filter3, filter4, filter5, filter6];

    var check_filter = filter.check(req.query, filters, res);
    if (check_filter[0] < 0)  // Filter with error
        return;
    else if (check_filter[0] == 1){ // Filter OK
        switch(check_filter[1]) {
            case 0:  // status - group
                args = ["-f", "rules.get_rules_with_group", "-a", req.query.group + "," + req.query.status];
                break;
            case 1:  // status - level
                args = ["-f", "rules.get_rules_with_level", "-a", req.query.level + "," + req.query.status];
                break;
            case 2:  // status - file
                args = ["-f", "rules.get_rules_with_file", "-a", req.query.file + "," + req.query.status];
                break;
            case 3: // status
                args = ["-f", "rules.get_rules", "-a", req.query.status];
                break;
            case 4:  // group
                args = ["-f", "rules.get_rules_with_group", "-a", req.query.group];
                break;
            case 5:  // level
                args = ["-f", "rules.get_rules_with_level", "-a", req.query.level];
                break;
            case 6:  // file
                args = ["-f", "rules.get_rules_with_file", "-a", req.query.file];
                break;
        }
    }else { // No filter
        args = ["-f", "rules.get_rules"];
    }

    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// GET /rules/groups
router.get('/groups', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /rules/groups");
    var args = ["-f", "rules.get_groups"]
    execute.exec(wazuh_control, args, function (data) {res_h.send(res, data);});
})

// GET /rules/files
router.get('/files', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /rules/files");
    var args = [];

    var filter0 = {'status':'alphanumeric_param'};
    var filter1 = {'download':'alphanumeric_param'};
    var filters = [filter0, filter1];

    var check_filter = filter.check(req.query, filters, res);
    if (check_filter[0] < 0)  // Filter with error
        return;
    else if (check_filter[0] == 1){ // Filter OK
        switch(check_filter[1]) {
            case 0: // status
                args = ["-f", "rules.get_rules_files", "-a", req.query.status];
                break;
            case 1: // download
                res_h.send_file(req.query.download, res);
                return;
        }
    }else { // No filter
        args = ["-f", "rules.get_rules_files"];
    }

    execute.exec(wazuh_control, args, function (data) {res_h.send(res, data);});
})

// GET /rules/:rule_id
router.get('/:rule_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /rules/:rule_id");
    var filters = [{'rule_id':'numbers'}];

    var check_filter = filter.check(req.params, filters, res);
    if (check_filter[0] < 0)  // Filter with error
        return;

    var args = ["-f", "rules.get_rule", "-a", req.params.rule_id];

    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });

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
