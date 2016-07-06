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
var common = require('./common.js');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

describe('App', function() {

    describe('Authentication', function() {

        it('should return error due to wrong password', function(done) {
            request(common.url)
            .get("/")
            .auth(common.credentials.user, 'random')
            .expect("Content-type",/json/)
            .expect(401)
            .end(function(err,res){
                if (err) return done(err);

                res.status.should.equal(401);
                done();
            });
        });

        it('should return home page', function(done) {
            request(common.url)
            .get("/")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.status.should.equal(200);
                res.body.error.should.equal(0);
                done();
            });
        });

    });

    describe('Requests', function() {

        it('should return error due to inexistent request', function(done) {
            request(common.url)
            .get("/random")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(404)
            .end(function(err,res){
                if (err) return done(err);

                res.status.should.equal(404);
                res.body.error.should.equal(603);
                done();
            });
        });

        it('should return API version', function(done) {
            request(common.url)
            .get("/version")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.status.should.equal(200);
                res.body.error.should.equal(0);
                done();
            });
        });

    });
});
