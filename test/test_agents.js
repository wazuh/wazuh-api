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

var should = require('should');
var assert = require('assert');
var request = require('supertest');

var url = 'https://127.0.0.1:55000';
var credentials = {'user':'foo', 'password':'bar'};

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

describe('Agents', function() {

    describe('Requests', function() {

        it('/agents', function(done) {
            request(url)
            .get("/agents")
            .auth(credentials.user, credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                res.status.should.equal(200);
                res.body.error.should.equal(0);
                done();
            });
        });

    });
});
