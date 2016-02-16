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

// Modules
var express = require('express');
var bodyParser = require('body-parser');
var auth = require("http-auth");
var fs = require('fs');
var https = require('https');
var logger = require('./helpers/logger');
var config = require('./config.js');

/********************************************/
/* Config APP
/********************************************/
port = process.env.PORT || config.port;

var app = express();

// Basic authentication
var auth_secure = auth.basic({
    realm: "OSSEC API",
    file: __dirname + "/ssl/htpasswd"
});
app.use(auth.connect(auth_secure));

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended: true}))

app.use(require('./controllers'))

// Certs
var options = {
  key: fs.readFileSync(__dirname + '/ssl/server.key'),
  cert: fs.readFileSync(__dirname + '/ssl/server.crt')
};
/********************************************/

// Create server
var server = https.createServer(options, app).listen(port, function(){
    logger.log("Listening on: https://" + server.address().address + ":" + port);
});
