/**
 * Wazuh RESTful API
 * Copyright (C) 2015-2018 Wazuh, Inc. All rights reserved.
 * Wazuh.com
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

 /*
    Function used in API requests that return a list with strings.
    Examples:
        GET/agents/os/summary
        GET/rootcheck/:agent_id/pci

    Field descritions:
    * entrypoint_name -> Name of the entrypoint (example: /agents, /agents/os/summary)
    * req -> parameter req
    * res -> parameter res
    * apiCacheGroup -> api cache group of the API call
    * param_checks -> Input validation checks for arguments in req.params.
    * query_checks -> Input validation checks for arguments in req.query.
 */
exports.single_field_array_request = function(entrypoint_name, req, res, apicacheGroup, param_checks, query_checks) {
    if(!param_checks || typeof param_checks !== 'object'){
        param_checks = {};
    }

    if(!query_checks || typeof query_checks !== 'object'){
        query_checks = {};
    }

    logger.debug(req.connection.remoteAddress + " GET " + entrypoint_name);

    req.apicacheGroup = apicacheGroup;

    var data_request = {'function': entrypoint_name, 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param',
                   'search':'search_param', 'q':'query_param'};

    if (!filter.check(req.query, Object.assign({}, filters, query_checks), req, res))  // Filter with error
        return;

    if (!filter.check(req.params, param_checks, req, res))  // Filter with error
        return;

    if ('offset' in req.query)
        data_request['arguments']['offset'] = Number(req.query.offset);
    if ('limit' in req.query)
        data_request['arguments']['limit'] = Number(req.query.limit);
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('q' in req.query)
        data_request['arguments']['q'] = req.query.q;

    filters = {}

    for (extra in Object.assign({}, query_checks, param_checks)) {
        if (extra in req.query) {
            if (query_checks[extra] == 'select_param')
                data_request['arguments'][extra] = filter.select_param_to_json(req.query[extra]);
            else if (extra == 'summary')
                data_request['arguments'][extra] = req.query[extra] === 'yes'
            else if (!(extra in data_request['arguments']))
                filters[extra] = req.query[extra];
        } else if (extra in req.params)
            data_request['arguments'][extra] = req.params[extra];
    }

    if (Object.keys(filters).length > 0) data_request['arguments']['filters'] = filters

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
}

 /*
    Function used in API requests that return a list with dictionaries. Its the same as "single_field_array_request" but includes field "select".
    Examples:
        GET/agents
        GET/rootcheck/:agent_id
 */
exports.array_request = function (entrypoint_name, req, res, apicacheGroup, param_checks, query_checks) {
    if(!param_checks || typeof param_checks !== 'object'){
        param_checks = {};
    }

    if(!query_checks || typeof query_checks !== 'object'){
        query_checks = {};
    }
    query_checks['select'] = 'select_param';
    this.single_field_array_request(entrypoint_name, req, res, apicacheGroup, param_checks, query_checks);
}
