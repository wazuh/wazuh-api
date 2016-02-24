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
var logger = require('./helpers/logger');
var config = require('./config.js');

/********************************************/
/* Config APP
/********************************************/
port = process.env.PORT || config.port;

var app = express();

// Basic authentication
if (config.basic_auth.toLowerCase() == "yes"){
    var auth_secure = auth.basic({
        realm: "OSSEC API",
        file: __dirname + "/ssl/htpasswd"
    });
    app.use(auth.connect(auth_secure));
}

// Certs
var options;
if (config.https.toLowerCase() == "yes"){
    options = {
      key: fs.readFileSync(__dirname + '/ssl/server.key'),
      cert: fs.readFileSync(__dirname + '/ssl/server.crt')
    };
}

// Body
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended: true}))

// Controllers
app.use(require('./controllers'))

/********************************************/

// Create server
if (config.https.toLowerCase() == "yes"){
    var https = require('https');
    var server = https.createServer(options, app).listen(port, function(){
        logger.log("Listening on: https://" + server.address().address + ":" + port);
    });
}
else{
    var http = require('http');
    var server = http.createServer(app).listen(port, function(){
        logger.log("Listening on: http://" + server.address().address + ":" + port);
    });
}

