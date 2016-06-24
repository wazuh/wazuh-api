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

// GET /manager/status - Get manager status
router.get('/status', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/status");
    var args = ["-f", "/manager/status"]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// GET /manager/info - Get manager info
router.get('/info', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/info");
    var args = ["-f", "/manager/info"]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// GET /manager/configuration - Get manager configuration
router.get('/configuration', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/configuration");
    var args = []
    var filter0 = {'section':'names', 'field': 'names'};
    var filter1 = {'section':'names'};

    var filters = [filter0, filter1];

    var check_filter = filter.check(req.query, filters, res);
    if (check_filter[0] < 0)  // Filter with error
        return;
    else if (check_filter[0] == 1){ // Filter OK
        switch(check_filter[1]) {
            case 0:  // section - field
                args = ["-f", "/manager/configuration", "-a", req.query.section + "," + req.query.field];
                break;
            case 1:  // section
                args = ["-f", "/manager/configuration", "-a", req.query.section];
                break;
        }
    }else { // No filter
        args = ["-f", "/manager/configuration"]
    }

    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// GET /manager/configuration/test - Test configuration
router.get('/configuration/test', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/configuration/test");
    var args = ["-f", "/manager/configuration/test"]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// GET /manager/stats - Stats
router.get('/stats', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/stats");

    var args = []
    var filter0 = {'date':'dates'};

    var filters = [filter0];

    var check_filter = filter.check(req.query, filters, res);
    if (check_filter[0] < 0)  // Filter with error
        return;
    else if (check_filter[0] == 1){ // Filter OK
        switch(check_filter[1]) {
            case 0:  // date
                var date_arg = req.query.date.substring(0, 4) + "," + req.query.date.substring(4, 6) + "," + req.query.date.substring(6, 8)
                args = ["-f", "/manager/stats", "-a", date_arg]
                break;
        }
    }else { // No filter
        var moment = require('moment');
        date = moment().format('YYYYMMDD')
        var date_arg = date.substring(0, 4) + "," + date.substring(4, 6) + "," + date.substring(6, 8)
        args = ["-f", "/manager/stats", "-a", date_arg]
    }

    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// GET /manager/stats/hourly - Stats hourly averages.
router.get('/stats/hourly', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/stats/hourly");
    var args = ["-f", "/manager/stats/hourly",]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// GET /manager/stats/weekly - Stats weekly-hourly averages
router.get('/stats/weekly', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/stats/weekly");
    var args = ["-f", "/manager/stats/weekly",]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// GET /manager/update-ruleset/backups - Stats weekly-hourly averages
router.get('/update-ruleset/backups', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/update-ruleset/backups");
    var args = ["-f", "/manager/update-ruleset/backups",]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// GET /manager/logs - Logs
router.get('/logs', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/logs");
    var args = []

    var filter0 = {'type_log':'names', 'category':'names'};
    var filter1 = {'type_log':'names'};
    var filter2 = {'category':'names'};

    var filters = [filter0, filter1, filter2];

    var check_filter = filter.check(req.query, filters, res);
    if (check_filter[0] < 0)  // Filter with error
        return;
    else if (check_filter[0] == 1){ // Filter OK
        switch(check_filter[1]) {
            case 0:  // type_log - category
                args = ["-f", "/manager/logs", "-a", req.query.type_log + "," + req.query.category]
                break;
            case 1:  // type_log
                args = ["-f", "/manager/logs", "-a", req.query.type_log + ",all"]
                break;
            case 2:  // category
                args = ["-f", "/manager/logs", "-a", "all," + req.query.category]
                break;
        }
    }else { // No filter
        args = ["-f", "/manager/logs", "-a", "all,all"]
    }

    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// GET /manager/logs/summary - ossec.log summary
router.get('/logs/summary', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/logs/summary");
    var args = ["-f", "/manager/logs/summary",]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

/********************************************/
/* PUT
/********************************************/
// PUT /manager/start - Start manager
router.put('/start', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /manager/start");
    var args = ["-f", "PUT/manager/start"]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// PUT /manager/stop - Stop manager
router.put('/stop', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /manager/stop");
    var args = ["-f", "PUT/manager/stop"]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// PUT /manager/restart - Restart manager
router.put('/restart', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /manager/restart");
    var args = ["-f", "PUT/manager/restart"]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// PUT /manager/update-ruleset - update ruleset
router.put('/update-ruleset', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /manager/update-ruleset");
    var args = []
    var filter0 = {'type':'names', 'force': 'names'};
    var filter1 = {'type':'names'};
    var filter2 = {'force':'names'};

    var filters = [filter0, filter1, filter2];

    var check_filter = filter.check(req.query, filters, res);
    if (check_filter[0] < 0)  // Filter with error
        return;
    else if (check_filter[0] == 1){ // Filter OK
        switch(check_filter[1]) {
            case 0:  // type - force
                var second_argument = ""
                if (req.query.force == "yes")
                    var second_argument = "," + "True"

                args = ["-f", "PUT/manager/update-ruleset", "-a", req.query.type + second_argument];
                break;
            case 1:  // type
                args = ["-f", "PUT/manager/update-ruleset", "-a", req.query.type];
                break;
            case 2:  // force
                if (req.query.force == "yes")
                    args = ["-f", "PUT/manager/update-ruleset", "-a", "both, True"];
                else
                    args = ["-f", "PUT/manager/update-ruleset"]
                break;
        }
    }else { // No filter
        args = ["-f", "PUT/manager/update-ruleset"]
    }

    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// PUT /manager/update-ruleset/backups/:id- backup ruleset
router.put('/update-ruleset/backups/:id', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT/manager/update-ruleset/backups/:id");
    var check_filter = filter.check(req.params, [{'id':'names'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return;

    var args = ["-f", "PUT/manager/update-ruleset/backups/:id", "-a", req.params.id]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

/********************************************/
/* DELETE
/********************************************/


/********************************************/
/* PATCH
/********************************************/



module.exports = router;
