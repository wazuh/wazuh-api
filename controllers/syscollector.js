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
 * @api {get} /syscollector/:agent_id/os Get os info
 * @apiName GetOs_agent
 * @apiGroup OS
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {String} [select] List of selected fields.
 *
 * @apiDescription Returns the agent's OS info
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/000/os?pretty"
 *
 */
router.get('/:agent_id/os', function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /syscollector/:agent_id/os");

    var data_request = {'function': '/syscollector/:agent_id/os', 'arguments': {}};
    var filters = {'select':'select_param'};

    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;

    if (!filter.check(req.query, filters, req, res))
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /syscollector/:agent_id/hardware Get hardware info
 * @apiName GetHardware_agent
 * @apiGroup Hardware
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {String} [select] List of selected fields.
 *
 * @apiDescription Returns the agent's hardware info
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/000/hardware?pretty"
 *
 */
router.get('/:agent_id/hardware', function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /syscollector/:agent_id/hardware");

    var data_request = {'function': '/syscollector/:agent_id/hardware', 'arguments': {}};

    var filters = {'select':'select_param'};


    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;

    if (!filter.check(req.query, filters, req, res))
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;
    data_request['arguments']['filters']  = {};

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)


    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /syscollector/:agent_id/packages Get packages info
 * @apiName GetPackages_agent
 * @apiGroup Packages
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [select] List of selected fields.
 * @apiParam {String} [vendor] Filters by vendor.
 * @apiParam {String} [name] Filters by name.
 * @apiParam {String} [architecture] Filters by architecture.
 * @apiParam {String} [format] Filters by format.
 * @apiParam {String} [version] Filters by version.
 *
 * @apiDescription Returns the agent's packages info
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/000/packages?pretty&limit=2&offset=10&sort=-name"
 *
 */
router.get('/:agent_id/packages', function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /syscollector/:agent_id/packages");

    var data_request = {'function': '/syscollector/:agent_id/packages', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param',
                   'search':'search_param', 'select':'select_param',
                    'vendor': 'alphanumeric_param', 'name': 'alphanumeric_param',
                    'architecture': 'alphanumeric_param', 'format': 'alphanumeric_param', 'version' : 'alphanumeric_param'};


    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;

    if (!filter.check(req.query, filters, req, res))
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;
    data_request['arguments']['filters']  = {};

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)
    if ('offset' in req.query)
        data_request['arguments']['offset'] = Number(req.query.offset);
    if ('limit' in req.query)
        data_request['arguments']['limit'] = Number(req.query.limit);
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('vendor' in req.query)
        data_request['arguments']['filters']['vendor'] = req.query.vendor
    if ('name' in req.query)
        data_request['arguments']['filters']['name'] = req.query.name
    if ('architecture' in req.query)
        data_request['arguments']['filters']['architecture'] = req.query.architecture
    if ('format' in req.query)
        data_request['arguments']['filters']['format'] = req.query.format
    if ('version' in req.query)
        data_request['arguments']['filters']['version'] = req.query.version

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

module.exports = router;
