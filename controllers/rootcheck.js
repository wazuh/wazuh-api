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
 * @api {get} /rootcheck/:agent_id Get rootcheck database
 * @apiName GetRootcheckAgent
 * @apiGroup Info
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {String} [pci] Filters by pci requirement.
 * @apiParam {String} [cis] Filters by CIS.
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns the rootcheck database of an agent.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/rootcheck/000?offset=0&limit=2&pretty"
 *
 */
router.get('/:agent_id', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /rootcheck/:agent_id");

    req.apicacheGroup = "rootcheck";

    var data_request = {'function': '/rootcheck/:agent_id', 'arguments': {}};

    var filters = {'status': 'names', 'cis':'alphanumeric_param', 'pci':'alphanumeric_param', 'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param'};

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;

    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('status' in req.query)
        data_request['arguments']['status'] = req.query.status;
    if ('cis' in req.query)
        data_request['arguments']['cis'] = req.query.cis;
    if ('pci' in req.query)
        data_request['arguments']['pci'] = req.query.pci;

    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /rootcheck/:agent_id/pci Get rootcheck pci requirements
 * @apiName GetRootcheckAgentPCI
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns the PCI requirements of all rootchecks of the agent.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/rootcheck/000/pci?offset=0&limit=10&pretty"
 *
 */
router.get('/:agent_id/pci', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /rootcheck/:agent_id/pci");

    req.apicacheGroup = "rootcheck";

    var data_request = {'function': '/rootcheck/:agent_id/pci', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param'};

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;

    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);

    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /rootcheck/:agent_id/cis Get rootcheck CIS requirements
 * @apiName GetRootcheckAgentCIS
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns the CIS requirements of all rootchecks of the specified agent.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/rootcheck/000/cis?offset=0&limit=10&pretty"
 *
 */
router.get('/:agent_id/cis', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /rootcheck/:agent_id/cis");

    req.apicacheGroup = "rootcheck";

    var data_request = {'function': '/rootcheck/:agent_id/cis', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param'};

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;

    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);

    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /rootcheck/:agent_id/last_scan Get last rootcheck scan
 * @apiName GetRootcheckAgentLastScan
 * @apiGroup Info
 *
 * @apiParam {Number} agent_id Agent ID.
 *
 * @apiDescription Returns the timestamp of the last rootcheck scan.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/rootcheck/000/last_scan?pretty"
 *
 */
router.get('/:agent_id/last_scan', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /rootcheck/:agent_id/last_scan");

    req.apicacheGroup = "rootcheck";

    var data_request = {'function': '/rootcheck/:agent_id/last_scan', 'arguments': {}};

    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {put} /rootcheck Run rootcheck scan in all agents
 * @apiName PutRootcheck
 * @apiGroup Run
 *
 *
 * @apiDescription Runs syscheck and rootcheck on all agents (Wazuh launches both processes simultaneously).
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X PUT "https://127.0.0.1:55000/rootcheck?pretty"
 *
 */
router.put('/', function(req, res) {
    logger.debug(req.connection.remoteAddress + " PUT /rootcheck");

    var data_request = {'function': 'PUT/rootcheck', 'arguments': {}};
    data_request['arguments']['all_agents'] = 1;
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {put} /rootcheck/:agent_id Run rootcheck scan in an agent
 * @apiName PutRootcheckAgentId
 * @apiGroup Run
 *
 * @apiParam {Number} agent_id Agent ID.
 *
 * @apiDescription Runs syscheck and rootcheck on a specified agent (Wazuh launches both processes simultaneously)
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X PUT "https://127.0.0.1:55000/rootcheck/000?pretty"
 *
 */
router.put('/:agent_id', function(req, res) {
    logger.debug(req.connection.remoteAddress + " PUT /rootcheck/:agent_id");

    var data_request = {'function': 'PUT/rootcheck', 'arguments': {}};

    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {delete} /rootcheck Clear rootcheck database
 * @apiName DeleteRootcheck
 * @apiGroup Clear
 *
 *
 * @apiDescription Clears the rootcheck database for all agents.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X DELETE "https://127.0.0.1:55000/rootcheck?pretty"
 *
 */
router.delete('/', function(req, res) {
    logger.debug(req.connection.remoteAddress + " DELETE /rootcheck");

    apicache.clear("rootcheck");

    var data_request = {'function': 'DELETE/rootcheck', 'arguments': {}};
    data_request['arguments']['all_agents'] = 1;
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {delete} /rootcheck/:agent_id Clear rootcheck database of an agent
 * @apiName DeleteRootcheckAgentId
 * @apiGroup Clear
 *
 * @apiParam {Number} agent_id Agent ID.
 *
 * @apiDescription Clears the rootcheck database for a specific agent.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X DELETE "https://127.0.0.1:55000/rootcheck/000?pretty"
 *
 */
router.delete('/:agent_id', function(req, res) {
    logger.debug(req.connection.remoteAddress + " DELETE /rootcheck/:agent_id");

    apicache.clear("rootcheck");

    var data_request = {'function': 'DELETE/rootcheck', 'arguments': {}};

    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})



module.exports = router;
