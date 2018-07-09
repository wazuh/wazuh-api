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
var jwt = require('jsonwebtoken');
var auth = require('../helpers/auth');


router.post('/authenticate', function (req, res) {
    var token = auth.get_token(req.body.name);
    res.status(200).send({ token: token });
});
;

module.exports = router;
