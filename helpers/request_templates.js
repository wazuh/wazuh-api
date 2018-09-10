/**
 * API RESTful for OSSEC
 * Copyright (C) 2015-2018 Wazuh, Inc.All rights reserved.
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
    * extra_arguments -> extra arguments needed in the API call (example: group id, agent id)
    * param_checks -> type of the extra arguments (example: group_id: names, agent_id:numbers)
    * extra_query_checks -> fields types to check in the request's query (example: status: names, files: path...)
    * extra_filters -> extra parameters in the query (examples: status, filename, etc)
 */
exports.single_field_array_request = function(entrypoint_name, req, res, apicacheGroup, extra_arguments={}, param_cheks={}, extra_query_cheks={}, extra_filters={}) {
    logger.debug(req.connection.remoteAddress + " GET " + entrypoint_name);

    req.apicacheGroup = apicacheGroup;

    var data_request = {'function': entrypoint_name, 'arguments': extra_arguments};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param',
                   'search':'search_param', 'q':'query_param'};

    if (!filter.check(req.query, Object.assign({}, filters, extra_query_cheks, extra_filters), req, res))  // Filter with error
        return;

    if (!filter.check(req.params, param_cheks, req, res))  // Filter with error
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

    for (extra in extra_query_cheks) {
        if (extra in req.query) {
            if (extra == 'select' || extra == 'fields')
                data_request['arguments'][extra] = filter.select_param_to_json(req.query[extra]);
            else
                data_request['arguments'][extra] = req.query[extra];
        }
    }

    if (Object.keys(extra_filters).length > 0) {
        data_request['arguments']['filters'] = {}
        for (extra in extra_filters) {
            if (extra in req.query)
                data_request['arguments']['filters'][extra] = req.query[extra].toLowerCase();
        }
    }

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
}

 /*
    Function used in API requests that return a list with dictionaries. Its the same as "single_field_array_request" but includes field "select".
    Examples:
        GET/agents
        GET/rootcheck/:agent_id
 */
exports.array_request = function (entrypoint_name, req, res, apicacheGroup, extra_arguments={}, param_cheks={}, extra_query_cheks={}, extra_filters={}) {
    extra_query_cheks['select'] = 'select_param';
    this.single_field_array_request(entrypoint_name, req, res, apicacheGroup, extra_arguments, param_cheks, extra_query_cheks, extra_filters);
}
