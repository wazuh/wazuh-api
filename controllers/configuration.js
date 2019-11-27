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
 * @api {get} /agents/configuration/validation Check an agent configuration
 * @apiName PutAgentConfiguration
 * @apiGroup Files
 *
 * @apiDescription Returns the result of validate an agent configuration
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X PUT -H 'Content-type: application/xml' -d @agent.conf.xml "https://127.0.0.1:55000/agents/configuration/validation?pretty"
 *
 */
router.put('/configuration/validation', function(req, res) {
    logger.debug(req.connection.remoteAddress + " PUT /agents/configuration/validation");

    var data_request = {'function': 'PUT/agents/configuration/validation', 'arguments': {}};
    // create temporary file
    if (req.headers['content-type'] == 'application/json') {
        if (!filter.check_xml(req.body, req, res)) return;  // validate XML

        try {
            data_request['arguments']['configuration_type'] = req.body.type;
            data_request['arguments']['tmp_file'] = require('../helpers/files').tmp_file_creator(req.body.file);
        } catch(err) {
            res_h.bad_request(req, res, 702, err);
            return;
        }
    } else {
        res_h.bad_request(req, res, 804, req.headers['content-type']);
        return;
    }

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

module.exports = router;
