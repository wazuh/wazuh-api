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
 * @api {post} rules/edit Update local rules
 * @apiName PostUpdateFile
 * @apiGroup Groups
 *
 * @apiParam {String} xml_file File with rules.
 * @apiParam {String} file_name File name.
 *
 * @apiDescription Upload a local rule file.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -X POST -H 'Content-type: application/xml' -d @rules.xml "https://127.0.0.1:55000/files?path=/etc/rules&pretty"
 *
 */
router.post('/', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " POST /files");

    //req.apicacheGroup = "agents";

    var data_request = {'function': 'POST/files', 'arguments': {}};
    //var filters = {'file_name': 'names'};

    if (!filter.check(req.params, filters, req, res))  // Filter with error
        return;

    if (!filter.check_xml(req.body, req, res)) return;

    if ('path' in req.query)
        data_request['arguments']['path'] = req.query.path;

    data_request['arguments']['group_id'] = req.params.group_id;
    try {
        data_request['arguments']['xml_file'] = require('../helpers/files').tmp_file_creator(req.body);
    } catch(err) {
        res_h.bad_request(req, res, 702, err);
        return;
    }
    data_request['arguments']['file_name'] = req.params.file_name;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


module.exports = router;
