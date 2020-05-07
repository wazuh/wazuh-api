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
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=10] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [select] List of selected fields separated by commas.
 * @apiParam {String} [q] Query to filter results by. For example q="id=T1010"
 * @apiParam {String} [id] Filter by attack ID.
 * @apiParam {String} [phase_name] Filter by phase name.
 * @apiParam {String} [platform_name] Filter by platform name.
 * @apiParam {String} [search] Looks for elements with the specified string.
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
                   'id': 'search_param', 'phase_name': 'search_param',
                   'platform_name': 'names', 'search': 'search_param', 'sort':'sort_param', 'select': 'select_param'};

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;

    if ('offset' in req.query)
        data_request['arguments']['offset'] = Number(req.query.offset);
    if ('limit' in req.query)
        data_request['arguments']['limit'] = Number(req.query.limit);
    if ('id' in req.query)
        data_request['arguments']['id'] = req.query.id;
    if ('phase_name' in req.query)
        data_request['arguments']['phase_name'] = req.query.phase_name;
    if ('platform_name' in req.query)
        data_request['arguments']['platform_name'] = req.query.platform_name;
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select);
    if ('q' in req.query)
        data_request['arguments']['q'] = req.query.q;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

module.exports = router;
