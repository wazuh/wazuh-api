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
 * @api {put} /configuration/validation/:type Check a specified configuration
 * @apiName PutConfigurationValidation
 * @apiGroup Files
 *
 * @apiDescription Returns the result of validate a Wazuh configuration
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -H 'Content-type: application/xml' -X PUT -d @/var/ossec/etc/shared/default/agent.conf "https://localhost:55000/configuration/validation/manager?pretty&wait_for_complete" -k
 *
 */
router.put('/validation/:type', function(req, res) {
    logger.debug(req.connection.remoteAddress + " PUT /configuration/validation/:type");

    var data_request = {'function': 'PUT/configuration/validation/:type', 'arguments': {}};
    // create temporary file
    if (req.headers['content-type'] == 'application/xml') {
        try {
            data_request['arguments']['configuration_type'] = req.params.type;
            data_request['arguments']['tmp_file'] = require('../helpers/files').tmp_file_creator(req.body);
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
