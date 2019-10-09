/**
 * Wazuh RESTful API
 * Copyright (C) 2015-2019 Wazuh, Inc. All rights reserved.
 * Wazuh.com
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


var router = require('express').Router();

/**
 * @api {get} /mitre Get information from Mitre database
 * @apiName GetMitre
 * @apiGroup Mitre
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=10] Maximum number of elements to return.
 * @apiParam {String} [q] Query to filter results by. For example q="attack=T1010"
 * @apiParam {String} [attack] Filter by attack ID.
 * @apiParam {String} [phase] Filter by phase name.
 * @apiParam {String} [platform] Filter by platform name.
 *
 * @apiDescription Returns information from Mitre database
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/mitre?limit=2&offset=4&pretty"
 *
 */
router.get('/', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /mitre");

    req.apicacheGroup = "mitre";

    var data_request = {'function': '/mitre', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'q': 'query_param',
                   'attack': 'search_param', 'phase': 'search_param', 'platform': 'names'};

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;

    if ('offset' in req.query)
        data_request['arguments']['offset'] = Number(req.query.offset);
    if ('limit' in req.query)
        data_request['arguments']['limit'] = Number(req.query.limit);
    if ('attack' in req.query)
        data_request['arguments']['attack'] = req.query.attack;
    if ('phase' in req.query)
        data_request['arguments']['phase'] = req.query.phase;
    if ('platform' in req.query)
        data_request['arguments']['platform'] = req.query.platform;
    if ('q' in req.query)
        data_request['arguments']['q'] = req.query.q;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

module.exports = router;
