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

describe('App', function() {

    describe('Authentication', function() {

        it('should return error due to wrong password', function(done) {
            request(url)
            .get("/")
            .auth(credentials.user, 'random')
            .expect("Content-type",/json/)
            .expect(401)
            .end(function(err,res){
                res.status.should.equal(401);
                done();
            });
        });

        it('should return home page', function(done) {
            request(url)
            .get("/")
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

    describe('Requests', function() {

        it('should return error due to inexistent request', function(done) {
            request(url)
            .get("/random")
            .auth(credentials.user, credentials.password)
            .expect("Content-type",/json/)
            .expect(404)
            .end(function(err,res){
                res.status.should.equal(404);
                res.body.error.should.equal(603);
                done();
            });
        });

        it('should return API version', function(done) {
            request(url)
            .get("/version")
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
