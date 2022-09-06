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
var common  = require('./common.js');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

describe('Active Response', function() {

    describe('PUT/active-response/:agent_id', function() {

        it('Request', function(done) {
            request(common.url)
            .put("/active-response/001")
            .send({'command':'restart-ossec0', 'arguments':[]})
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.equal("Command sent.");
                done();
            });
        });

        it('Command not found', function(done) {
            request(common.url)
            .put("/active-response/000")
            .send({'command':'random', 'arguments':[]})
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1655);
                done();
            });
        });

        it('Custom command', function(done) {
            request(common.url)
            .put("/active-response/000")
            .send({'command':'random', 'arguments':[], 'custom': true})
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.equal("Command sent.");
                done();
            });
        });

        it('Wrong custom parameter', function(done) {
            request(common.url)
            .put("/active-response/000")
            .send({'command':'restart-ossec0', 'arguments':[], 'custom': 'wrong'})
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(618);
                done();
            });
        });

        it('Wrong arguments parameter', function(done) {
            request(common.url)
            .put("/active-response/000")
            .send({'command':'restart-ossec0', 'arguments': 'wrong'})
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(624);
                done();
            });
        });

        it('Agent does not exist', function(done) {
            request(common.url)
            .put("/active-response/999")
            .send({'command':'restart-ossec0', 'arguments':[]})
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(1701);
                done();
            });
        });

        it('Agent ID not valid', function(done) {
            request(common.url)
            .put("/active-response/random")
            .send({'command':'restart-ossec0', 'arguments':[]})
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(600);
                done();
            });
        });

        it('Wrong command (unsafe path - Ubuntu)', function(done) {
            request(common.url)
            .put("/active-response/000")
            .send({'command':'../../../test.sh', 'arguments':[], 'custom': true})
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(602);
                done();
            });
        });

        it('Wrong command (unsafe path - Windows)', function(done) {
            request(common.url)
            .put("/active-response/000")
            .send({'command':'..\\..\\..\\test.ps1', 'arguments':[], 'custom': true})
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(602);
                done();
            });
        });

        it('Wrong command (unsafe path with ! - Ubuntu)', function(done) {
            request(common.url)
            .put("/active-response/000")
            .send({'command':'!../../../test.sh', 'arguments':[]})
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(602);
                done();
            });
        });

        it('Wrong command (unsafe path with ! - Windows)', function(done) {
            request(common.url)
            .put("/active-response/000")
            .send({'command':'!..\\..\\..\\test.ps1', 'arguments':[]})
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(602);
                done();
            });
        });

        it('Other valid commands (Ubuntu)', function(done) {
            request(common.url)
            .put("/active-response/000")
            .send({'command':'./test.sh', 'arguments':[], 'custom': true})
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.equal("Command sent.");
                done();
            });
        });

        it('Other valid commands (Windows)', function(done) {
            request(common.url)
            .put("/active-response/000")
            .send({'command':'.\\test.ps1', 'arguments':[], 'custom': true})
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.equal("Command sent.");
                done();
            });
        });
    })
})
