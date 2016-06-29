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

    var data_request = {'function': '/rules', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'status':'alphanumeric_param', 'group':'alphanumeric_param', 'level':'ranges', 'file':'alphanumeric_param', 'pci':'alphanumeric_param'};

    if (!filter.check(req.query, filters, res))  // Filter with error
        return;

    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;
    if ('status' in req.query)
        data_request['arguments']['status'] = req.query.status;
    if ('group' in req.query)
        data_request['arguments']['group'] = req.query.group;
    if ('level' in req.query)
        data_request['arguments']['level'] = req.query.level;
    if ('file' in req.query)
        data_request['arguments']['file'] = req.query.file;
    if ('pci' in req.query)
        data_request['arguments']['pci'] = req.query.pci;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// GET /rules/groups
router.get('/groups', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /rules/groups");
    var data_request = {'function': '/rules/groups', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers'};

    if (!filter.check(req.query, filters, res))  // Filter with error
        return;

    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// GET /rules/pci
router.get('/pci', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /rules/pci");
    var data_request = {'function': '/rules/pci', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers'};

    if (!filter.check(req.query, filters, res))  // Filter with error
        return;

    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// GET /rules/files
router.get('/files', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /rules/files");

    var data_request = {'function': '/rules/files', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'status':'alphanumeric_param', 'download':'alphanumeric_param'};

    if (!filter.check(req.query, filters, res))  // Filter with error
        return;

    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;
    if ('status' in req.query)
        data_request['arguments']['status'] = req.query.status;

    if ('download' in req.query)
        res_h.send_file(req.query.download, res);
    else
        execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// GET /rules/:rule_id
router.get('/:rule_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /rules/:rule_id");

    var data_request = {'function': '/rules', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers'};

    if (!filter.check(req.query, filters, res))  // Filter with error
        return;

    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;

    if (!filter.check(req.params, {'rule_id':'numbers'}, res))  // Filter with error
        return;

    data_request['arguments']['id'] = req.params.rule_id;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
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
