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


/**
 * @api {get} /unique/agents 
 * @apiName GetUniqueAgents
 * @apiGroup Agents
 *
 * @apiDescription 
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/unique/agents?pretty"
 *
 */
router.get('/agents', cache(), function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /unique/agents");

    req.apicacheGroup = "manager";

    var data_request = { 'function': '/unique/agents', 'arguments': {} };
    var filters = {
        'select': 'select_param'
    };
    
    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select);
    
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

module.exports = router;
