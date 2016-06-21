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

/********************************************/
/* GET
/********************************************/

// GET /decoders
router.get('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /decoders");
    var args = [];

    var check_filter = filter.check(req.query, [{'file':'paths'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return;
    else if (check_filter[0] == 1){ // Filter OK
        switch(check_filter[1]) {
            case 0:  // status - group
                args = ["-f", "/decoders?file", "-a", req.query.file];
                break;
        }
    }else { // No filter
        args = ["-f", "/decoders"];
    }
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})


// GET /decoders/files
router.get('/files', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /decoders/files");
    var args = ["-f", "/decoders/files"];
    execute.exec(wazuh_control, args, function (data) {res_h.send(res, data);});
})

// GET /decoders/parents
router.get('/parents', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /decoders/parents");
    var args = ["-f", "/decoders/parents"];
    execute.exec(wazuh_control, args, function (data) {res_h.send(res, data);});
})

// GET /decoders/:decoder_name
router.get('/:decoder_name', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /decoders/:decoder_name");
    var filters = [{'decoder_name':'names'}];

    var check_filter = filter.check(req.params, filters, res);
    if (check_filter[0] < 0)  // Filter with error
        return;

    var args = ["-f", "/decoders/:decoder_name", "-a", req.params.decoder_name];

    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });

})
/********************************************/
/* PUT
/********************************************/


/********************************************/
/* DELETE
/********************************************/


/********************************************/
/* POST
/********************************************/



module.exports = router;
