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
var manager = require('../models/manager');
var rh = require('../helpers/response_handler');
var logger = require('../helpers/logger');
var validator = require('../helpers/input_validation');

/**
 * GET /manager/status - Get manager status
 *
 * PUT /manager/start - Start manager
 * PUT /manager/stop - sTOP manager
 *
**/

/********************************************/
/* GET
/********************************************/

// Get manager status: /status
router.get('/status', function(req, res) {
    logger.log(req.host + " GET /manager/status");
    manager.status(function (data) {
        rh.cmd(data, res);
    });
})


/********************************************/
/* PUT
/********************************************/
// Start manager: /start
router.put('/start', function(req, res) {
    logger.log(req.host + " PUT /manager/start");
    manager.start(function (data) {
        rh.cmd(data, res);
    });
})

// Stop manager: /stop
router.put('/stop', function(req, res) {
    logger.log(req.host + " PUT /manager/stop");
    manager.stop(function (data) {
        rh.cmd(data, res);
    });
})

/********************************************/
/* DELETE
/********************************************/


/********************************************/
/* PATCH
/********************************************/



module.exports = router;