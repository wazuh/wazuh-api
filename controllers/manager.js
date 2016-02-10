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
var jsutils = require('../helpers/js_utils');

/**
 * GET /manager/status - Get manager status
 * GET /manager/settings - Get manager settings
 *   GET /manager/settings?section=rules - Get rules in ossec.conf
 *
 * PUT /manager/start - Start manager
 * PUT /manager/stop - Stop manager
 *
**/


/********************************************/
/* GET
/********************************************/

// GET /manager/status - Get manager status
router.get('/status', function(req, res) {
    logger.log(req.host + " GET /manager/status");
    manager.status(function (data) {
        rh.cmd(data, res);
    });
    
})

// GET /manager/settings - Get manager settings
router.get('/settings', function(req, res) {
    logger.log(req.host + " GET /manager/settings");
    
    // Filter
    json_filter = {};
    if (!jsutils.isEmptyObject(req.query)){

        if((req.query.hasOwnProperty('section') || req.query.hasOwnProperty('field')) && Object.keys(req.query).length <= 2){
            json_filter = {}
            if (req.query.hasOwnProperty('section'))
                json_filter['section'] = req.query.section;
            if (req.query.hasOwnProperty('field'))
                json_filter['field'] = req.query.field;
        }
        else{
            rh.bad_request("604", "Just 'section and field' filter", res);
        }
    }

    manager.settings(json_filter, function (data) {
        rh.cmd(data, res);
    });
})


/********************************************/
/* PUT
/********************************************/
// PUT /manager/start - Start manager
router.put('/start', function(req, res) {
    logger.log(req.host + " PUT /manager/start");
    manager.start(function (data) {
        rh.cmd(data, res);
    });
})

// PUT /manager/stop - Stop manager
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