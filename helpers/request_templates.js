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

exports.single_field_array_request = function(entrypoint_name, req, res, apicacheGroup, extra_arguments={}, param_cheks={}, extra_query_cheks={}) {
    logger.debug(req.connection.remoteAddress + " GET " + entrypoint_name);

    req.apicacheGroup = apicacheGroup;

    var data_request = {'function': entrypoint_name, 'arguments': extra_arguments};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param',
                   'search':'search_param', 'q':'query_param'};

    if (!filter.check(req.query, Object.assign({}, filters, extra_query_cheks), req, res))  // Filter with error
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
            if (extra == 'select')
                data_request['arguments'][extra] = filter.select_param_to_json(req.query[extra]);
            else
                data_request['arguments'][extra] = req.query.extra;
        }
    }

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
}


exports.array_request = function (entrypoint_name, req, res, apicacheGroup, extra_arguments={}, param_cheks={}, extra_query_cheks={}) {
    extra_query_cheks['select'] = 'select_param';
    this.single_field_array_request(entrypoint_name, req, res, apicacheGroup, extra_arguments, param_cheks, extra_query_cheks);
}
