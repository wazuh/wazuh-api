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

var should  = require('should');
var assert  = require('assert');
var request = require('supertest');
var fs      = require('fs');
var common  = require('./common.js');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

describe('Configuration', function() {

    describe('PUT/configuration/validation/:type', function() {
        agent_xml = fs.readFileSync('./test/data/agent.conf.xml', 'utf8')

        it('Request', function(done) {
            request(common.url)
            .post("/configuration/validation/remote")
            .auth(common.credentials.user, common.credentials.password)
            .set('Content-Type', 'application/xml')
            .send(agent_xml)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.list;
                done();
            });
        });
    })
}); // Configuration
