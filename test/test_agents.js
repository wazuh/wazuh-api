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

describe('Agents', function() {

    describe('GET/agents', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/agents")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['status', 'ip', 'id', 'name']);
                done();
            });
        });

        it('Pagination', function(done) {
            request(common.url)
            .get("/agents?offset=0&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                res.body.data.items[0].should.have.properties(['status', 'ip', 'id', 'name']);
                res.body.data.items[0].id.should.have.equal('000');
                res.body.data.items[0].status.should.have.equal('active');
                done();
            });
        });

        it('Sort', function(done) {
            request(common.url)
            .get("/agents?sort=-id")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['status', 'ip', 'id', 'name']);
                done();
            });
        });

        it('Search', function(done) {
            request(common.url)
            .get("/agents?search=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['status', 'ip', 'id', 'name']);
                done();
            });
        });

        it('Filters: status', function(done) {
            request(common.url)
            .get("/agents?status=aCtIvE")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['status', 'ip', 'id', 'name']);
                done();
            });
        });

        it('Filters: Invalid filter', function(done) {
            request(common.url)
            .get("/agents?random")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(604);
                done();
            });
        });

        it('Filters: Invalid filter - Extra field', function(done) {
            request(common.url)
            .get("/agents?status=aCtIvE&random")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(604);
                done();
            });
        });

    });  // GET/agents

    describe('GET/agents/summary', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/agents/summary")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.have.properties(['Active', 'Total', 'Disconnected', 'Never connected']);
                res.body.data['active'].should.be.above(0);
                res.body.data['total'].should.be.an.integer;
                res.body.data['disconnected'].should.be.an.integer;
                res.body.data['neverConnected'].should.be.an.integer;
                done();
            });
        });

    });  // GET/agents/summary

    describe('GET/agents/:agent_id', function() {

        it('Request (manager)', function(done) {
            request(common.url)
            .get("/agents/000")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.have.properties(['status', 'name', 'ip', 'dateAdd', 'version', 'os', 'id']);
                done();
            });
        });

        it('Request (agent)', function(done) {
            request(common.url)
            .get("/agents/001")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.have.properties(['status', 'name', 'ip', 'dateAdd', 'id']);  //version, lastKeepAlive, os
                done();
            });
        });

        it('Params: Bad agent id', function(done) {
            request(common.url)
            .get("/agents/abc")
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

        it('Errors: No agent', function(done) {
            request(common.url)
            .get("/agents/9999999")
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
    });  // GET/agents/:agent_id

    describe('GET/agents/:agent_id/key', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/agents/001/key")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.type('string');
                done();
            });
        });

        it('Params: Bad agent id', function(done) {
            request(common.url)
            .get("/agents/abc/key")
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

        it('Errors: No key', function(done) {
            request(common.url)
            .get("/agents/999999/key")
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
    });  // GET/agents/:agent_id/key

    describe('PUT/agents/:agent_name', function() {
        var agent_id = 0;

        after(function(done) {
            request(common.url)
            .delete("/agents/" + agent_id)
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err, res) {
                if (err) return done(err);
                done();
              });
        });

        it('Request', function(done) {

            request(common.url)
            .put("/agents/testingNewAgentPut")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.match(/^\d+$/);
                agent_id = res.body.data;
                done();
            });
        });

        it('Errors: Name already present', function(done) {

            request(common.url)
            .put("/agents/testingNewAgentPut")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(1705);
                res.body.message.should.be.type('string');
                done();
            });
        });

        it('Params: Bad agent name', function(done) {
            request(common.url)
            .put("/agents/testingNewAgent!!")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(601);
                done();
            });
        });

    });  // PUT/agents/:agent_name

    describe('DELETE/agents/:agent_id', function() {
        var agent_id = 0;

        before(function(done) {
            request(common.url)
            .put("/agents/TestingDeleteAgent")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err, res) {
                if (err) throw err;
                agent_id = res.body.data;
                done();
              });
        });

        it('Request', function(done) {

            request(common.url)
            .delete("/agents/" + agent_id)
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.type('string');
                done();
            });
        });

        it('Errors: ID is not present', function(done) {

            request(common.url)
            .delete("/agents/" + agent_id)
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(1701);
                res.body.message.should.be.type('string');
                done();
            });
        });

        it('Params: Bad agent id', function(done) {
            request(common.url)
            .delete("/agents/abc")
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

    });  // DELETE/agents/:agent_id

    describe('POST/agents', function() {
        describe('Any', function() {
            var agent_id = 0;

            after(function(done) {
                request(common.url)
                .delete("/agents/" + agent_id)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err, res) {
                    if (err) return done(err);
                    done();
                  });

            });

            it('Request', function(done) {

                request(common.url)
                .post("/agents")
                .send({'name':'NewAgentPost', 'ip':'any'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.match(/^\d+$/);
                    agent_id = res.body.data;
                    done();
                });
            });

            it('Errors: Name already present', function(done) {
                request(common.url)
                .post("/agents")
                .send({'name':'NewAgentPost', 'ip':'any'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(1705);
                    res.body.message.should.be.type('string');
                    done();
                });
            });

            it('Filters: Missing field name', function(done) {

                request(common.url)
                .post("/agents")
                .send({'ip':'any'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(400)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(604);
                    done();
                });
            });

            it('Filters: Invalid field', function(done) {

                request(common.url)
                .post("/agents")
                .send({'extraField': 'invalid', 'name': 'testagentpost', 'ip':'any'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(400)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(604);
                    done();
                });
            });

        });  // Any

        describe('IP Automatic', function() {
            var agent_id = 0;

            after(function(done) {
                request(common.url)
                .delete("/agents/" + agent_id)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err, res) {
                    if (err) return done(err);
                    done();
                  });

            });

            it('Request: Automatic IP', function(done) {

                request(common.url)
                .post("/agents")
                .send({'name':'NewAgentPost2'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.match(/^\d+$/);
                    agent_id = res.body.data;
                    done();
                });
            });

            it('Errors: Duplicated IP', function(done) {
                request(common.url)
                .post("/agents")
                .send({'name':'NewAgentPost3'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(1706);
                    done();
                });
            });
        });  // IP Automatic

        describe('IP', function() {
            var agent_id = 0;

            afterEach(function(done) {
                if (agent_id != 0){
                    request(common.url)
                    .delete("/agents/" + agent_id)
                    .auth(common.credentials.user, common.credentials.password)
                    .expect("Content-type",/json/)
                    .expect(200)
                    .end(function(err, res) {
                        if (err) return done(err);
                        agent_id = 0;
                        done();
                      });
                }
                else {
                    done();
                }

            });

            it('Request', function(done) {

                request(common.url)
                .post("/agents")
                .send({'name':'NewAgentPost4', 'ip': '192.246.247.248'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.match(/^\d+$/);
                    agent_id = res.body.data;
                    done();
                });
            });

            it('Filters: Bad IP', function(done) {

                request(common.url)
                .post("/agents")
                .send({'name':'NewAgentPost4', 'ip': 'A.B.C.D'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(400)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(606);
                    done();
                });
            });

            it('Filters: Bad IP 2', function(done) {

                request(common.url)
                .post("/agents")
                .send({'name':'NewAgentPost4', 'ip': '333.333.333.333'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(400)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(606);
                    done();
                });
            });
        });  // IP

    });  //POST/agents

    describe('PUT/agents/restart', function() {

        it('Request', function(done) {
            this.timeout(common.timeout);

            request(common.url)
            .put("/agents/restart")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.type('string');
                done();
            });
        });

    });  // PUT/agents/restart

    describe('PUT/agents/:agent_id/restart', function() {

        it('Request', function(done) {
            this.timeout(common.timeout);

            request(common.url)
            .put("/agents/001/restart")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.type('string');
                done();
            });
        });

        it('Params: Bad agent id', function(done) {
            request(common.url)
            .put("/agents/abc/restart")
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

        it('Request', function(done) {
            this.timeout(common.timeout);

            request(common.url)
            .put("/agents/000/restart")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(1703);
                done();
            });
        });

    });  // PUT/agents/:agent_id/restart

});  // Agents
