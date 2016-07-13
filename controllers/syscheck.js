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
 * @api {get} /syscheck/:agent_id/files Get syscheck files
 * @apiName GetSyscheckAgent
 * @apiGroup Database
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the begining to ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String="added","readded", "modified", "deleted"} [event] Filters files by event.
 * @apiParam {String} [file] Filters file by filename.
 * @apiParam {String="file","registry"} [filetype] Selects type of file.
 * @apiParam {String="yes", "no"} [summary] Returns a summary where each item has: scanDate, modificationDate, event and file.
 * @apiParam {String} [md5] Returns the files with the specified md5 hash.
 * @apiParam {String} [sha1] Returns the files with the specified sha1 hash.
 *
 * @apiDescription Returns the syscheck files of an agent.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscheck/000/files?offset=0&limit=2&pretty"
 *
 */
router.get('/:agent_id/files', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /syscheck/:agent_id/files");

    var data_request = {'function': '/syscheck/files', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param', 'event':'names', 'file':'paths', 'filetype':'names', 'summary':'names', 'md5':'hashes', 'sha1':'hashes'};

    if (!filter.check(req.query, filters, res))  // Filter with error
        return;
    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('event' in req.query)
        data_request['arguments']['event'] = req.query.event;
    if ('file' in req.query)
        data_request['arguments']['filename'] = req.query.file;
    if ('filetype' in req.query)
        data_request['arguments']['filetype'] = req.query.filetype;
    if ('summary' in req.query && req.query.summary == "yes")
        data_request['arguments']['summary'] = req.query.summary;
    if ('md5' in req.query)
        data_request['arguments']['md5'] = req.query.md5.toLowerCase();
    if ('sha1' in req.query)
        data_request['arguments']['sha1'] = req.query.sha1.toLowerCase();


    if (!filter.check(req.params, {'agent_id':'numbers'}, res))  // Filter with error
        return;
    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

/**
 * @api {get} /syscheck/:agent_id/last_scan Get last syscheck scan
 * @apiName GetSyscheckAgentLastScan
 * @apiGroup Database
 *
 * @apiParam {Number} agent_id Agent ID.
 *
 * @apiDescription Return the timestamp of the last syscheck scan.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscheck/000/last_scan?pretty"
 *
 */
router.get('/:agent_id/last_scan', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /syscheck/:agent_id/last_scan");

    var data_request = {'function': '/syscheck/:agent_id/last_scan', 'arguments': {}};

    if (!filter.check(req.params, {'agent_id':'numbers'}, res))  // Filter with error
        return;
    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})


/**
 * @api {put} /syscheck Run syscheck scan in all agents
 * @apiName PutSyscheckAgent
 * @apiGroup Run
 *
 *
 * @apiDescription Runs syscheck/rootcheck on all agents. This request has the same behavior that `PUT /rootcheck`_. Due to OSSEC launches both processes at once.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X PUT "https://127.0.0.1:55000/syscheck?pretty"
 *
 */
router.put('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /syscheck");

    var data_request = {'function': 'PUT/syscheck', 'arguments': {}};
    data_request['arguments']['all_agents'] = 1;
    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

/**
 * @api {put} /syscheck/:agent_id Run syscheck scan in an agent
 * @apiName PutSyscheckAgentId
 * @apiGroup Run
 *
 * @apiParam {Number} agent_id Agent ID.
 *
 * @apiDescription Runs syscheck/rootcheck on an agent. This request has the same behavior that `PUT /rootcheck/:agent_id`_. Due to OSSEC launches both processes at once.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X PUT "https://127.0.0.1:55000/syscheck/000?pretty"
 *
 */
router.put('/:agent_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /syscheck/:agent_id");

    var data_request = {'function': 'PUT/syscheck', 'arguments': {}};

    if (!filter.check(req.params, {'agent_id':'numbers'}, res))  // Filter with error
        return;
    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})


/**
 * @api {delete} /syscheck Clear syscheck database
 * @apiName DeleteSyscheckAgent
 * @apiGroup Clear
 *
 *
 * @apiDescription Clears the syscheck database for all agents.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X DELETE "https://127.0.0.1:55000/syscheck?pretty"
 *
 */
router.delete('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " DELETE /syscheck");

    var data_request = {'function': 'DELETE/syscheck', 'arguments': {}};
    data_request['arguments']['all_agents'] = 1;
    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

/**
 * @api {delete} /syscheck/:agent_id Clear syscheck database of an agent
 * @apiName PutSyscheckAgentId
 * @apiGroup Clear
 *
 * @apiParam {Number} agent_id Agent ID.
 *
 * @apiDescription Clears the syscheck database for an agent.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X DELETE "https://127.0.0.1:55000/syscheck/000?pretty"
 *
 */
router.delete('/:agent_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " DELETE /syscheck/:agent_id");

    var data_request = {'function': 'DELETE/syscheck', 'arguments': {}};

    if (!filter.check(req.params, {'agent_id':'numbers'}, res))  // Filter with error
        return;
    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})



module.exports = router;
