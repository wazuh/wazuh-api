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
                res.body.data.items[0].status.should.have.equal('Active');
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
                res.body.data.items[0].should.have.properties(['status', 'ip', 'id', 'name', 'dateAdd']);
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
                res.body.data['Active'].should.be.above(0);
                res.body.data['Total'].should.be.an.integer;
                res.body.data['Disconnected'].should.be.an.integer;
                res.body.data['Never connected'].should.be.an.integer;
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

    describe('PUT/agents/:agent_id/group/:group_id', function() {

        it('Request', function(done) {

            request(common.url)
            .put("/agents/001/group/webserver")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                done();
            });
        });

        it('Params: Bad agent name', function(done) {
            request(common.url)
            .put("/agents/001!/group/webserver")
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

        it('Params: Agent does not exist', function(done) {
            request(common.url)
            .put("/agents/1568/group/webserver")
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

    });  // PUT/agents/:agent_id/group/:group_id

    describe('PUT/agents/groups/:group_id', function() {

        after(function(done) {
            request(common.url)
            .delete("/agents/groups/newgroupcreated")
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
            .put("/agents/groups/newgroupcreated")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                done();
            });
        });

        it('Params: Bad group name', function(done) {
            request(common.url)
            .put("/agents/groups/!group")
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

        it('Params: Group already exists', function(done) {
            request(common.url)
            .put("/agents/groups/webserver")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1711);
                done();
            });
        });

    });  // PUT/agents/groups/:group_id

    describe('GET/agents/groups', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/agents/groups")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.array;
                done();
            });
        });

    });  // GET/agents/groups

    describe('GET/agents/groups/:group_id', function() {

        it('Request', function(done) {

            request(common.url)
            .get("/agents/groups/webserver")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['totalItems', 'items']);
                res.body.error.should.equal(0);
                done();
            });
        });

        it('Params: Bad group name', function(done) {
            request(common.url)
            .get("/agents/groups/web!-ña")
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

    });  // GET/agents/groups/:group_id

    describe('GET/agents/groups/:group_id/configuration', function() {

        it('Request', function(done) {

            request(common.url)
            .get("/agents/groups/webserver/configuration")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['totalItems', 'items']);
                res.body.error.should.equal(0);
                done();
            });
        });

        it('Params: Bad group name', function(done) {
            request(common.url)
            .get("/agents/groups/wñ!/configuration")
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

    });  // GET/agents/groups/:group_id/configuration

    describe('GET/agents/groups/:group_id/files', function() {

        it('Request', function(done) {

            request(common.url)
            .get("/agents/groups/webserver/files")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                done();
            });
        });

        it('Params: Bad group name', function(done) {
            request(common.url)
            .get("/agents/groups/wñ!/files")
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

    });  // GET/agents/groups/:group_id/files

    describe('GET/agents/groups/:group_id/files/:filename', function() {

        it('Request', function(done) {

            request(common.url)
            .get("/agents/groups/webserver/files/cis_debian_linux_rcl.txt")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                done();
            });
        });

        it('Params: Bad group name', function(done) {
            request(common.url)
            .get("/agents/groups/wñ!/files/cis_debian_linux_rcl.txt")
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

    });  // GET/agents/groups/:group_id/files/:filename

    describe('DELETE/agents/:agent_id/group', function() {

        it('Request', function(done) {

            request(common.url)
            .delete("/agents/001/group")
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
            .delete("/agents/54952/group")
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
            .delete("/agents/abc/group")
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

    });  // DELETE/agents/:agent_id/group

    describe('DELETE/agents/groups/:group_id', function() {

        it('Request', function(done) {

            request(common.url)
            .delete("/agents/groups/webserver")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                done();
            });
        });

        it('Params: Bad group id', function(done) {
            request(common.url)
            .delete("/agents/groups/webserverñ")
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

    });  // DELETE/agents/groups/:group_id

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
                res.body.data.should.be.type('object');
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

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['msg', 'failed_ids', 'affected_agents']);

                res.body.data.failed_ids[0].error.code.should.equal(1703);
                done();
            });
        });

    });  // PUT/agents/:agent_id/restart

});  // Agents
