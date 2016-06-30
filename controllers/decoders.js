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

// GET /decoders
router.get('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /decoders");

    var data_request = {'function': '/decoders', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'file':'paths'};

    if (!filter.check(req.query, filters, res))  // Filter with error
        return;

    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('file' in req.query)
        data_request['arguments']['file'] = req.query.file;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})


// GET /decoders/files
router.get('/files', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /decoders/files");

    var data_request = {'function': '/decoders/files', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param'};

    if (!filter.check(req.query, filters, res))  // Filter with error
        return;

    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// GET /decoders/parents
router.get('/parents', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /decoders/parents");

    var data_request = {'function': '/decoders', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param'};

    if (!filter.check(req.query, filters, res))  // Filter with error
        return;

    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);

    data_request['arguments']['parents'] = "True";

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// GET /decoders/:decoder_name
router.get('/:decoder_name', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /decoders/:decoder_name");

    var data_request = {'function': '/decoders/:decoder_name', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param'};

    if (!filter.check(req.query, filters, res))  // Filter with error
        return;

    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);

    if (!filter.check(req.params, {'decoder_name':'names'}, res))  // Filter with error
        return;

    data_request['arguments']['name'] = req.params.decoder_name;

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
