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

var express = require('express');
var router = express.Router();
var res_h = require('../helpers/response_handler');
var req_h = require('../helpers/request_handler');
var logger = require('../helpers/logger');
var validator = require('../helpers/input_validation');
var execute = require('../helpers/execute');
var config = require('../config.js');
var wazuh_control = config.api_path + "/models/wazuh-control.py";

/********************************************/
/* GET
/********************************************/

// GET /rules - Get rules list
router.get('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /rules");

    var args = ["-f", "rules.get_rules"]
        execute.exec(wazuh_control, args, function (data) {
        res_h.send(res, data);
    });

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
