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

describe('Manager', function() {

    describe('GET/manager/status', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/manager/status")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);

                res.body.data.should.have.properties(['wazuh-moduled', 'ossec-authd', 'ossec-monitord', 'ossec-logcollector', 'ossec-execd', 'ossec-remoted', 'ossec-syscheckd', 'ossec-analysisd', 'ossec-maild']);
                done();
            });
        });

    });  // GET/manager/status

    describe('GET/manager/info', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/manager/info")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.have.properties(['path', 'installation_date', 'version', 'type']);
                done();
            });
        });

    });  // GET/manager/info

    describe('GET/manager/configuration', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/manager/configuration")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.have.properties(['global', 'rules', 'syscheck', 'rootcheck', 'remote', 'localfile']);
                done();
            });
        });

        it('Filters: Missing field section', function(done) {
            request(common.url)
            .get("/manager/configuration?field=hi")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(604);
                res.body.message.should.be.an.string;
                done();
            });
        });

        it('Filters: Section', function(done) {
            request(common.url)
            .get("/manager/configuration?section=rules")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.have.properties(['decoder_dir', 'include', 'decoder']);
                res.body.data.include.should.be.instanceof(Array)
                done();
            });
        });

        it('Errors: Invalid Section', function(done) {
            request(common.url)
            .get("/manager/configuration?section=rulesa")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(1102);
                res.body.message.should.be.an.string;
                done();
            });
        });

        it('Filters: Section - field', function(done) {
            request(common.url)
            .get("/manager/configuration?section=rules&field=include")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.be.instanceof(Array)
                done();
            });
        });

        it('Errors: Invalid field', function(done) {
            request(common.url)
            .get("/manager/configuration?section=rules&field=includedd")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(1103);
                res.body.message.should.be.an.string;
                done();
            });
        });

        it('Filters: Invalid filter', function(done) {
            request(common.url)
            .get("/manager/configuration?random")
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
            .get("/manager/configuration?section=rules&field=included&random")
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

    });  // PUT/manager/configuration

    describe('PUT/manager/configuration/test', function() {

        it('Request', function(done) {
            request(common.url)
            .put("/manager/configuration/test")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.string;
                res.body.data.should.equal("OK");
                done();
            });
        });

    });  // PUT/manager/configuration/test

    describe('GET/manager/stats', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/manager/stats")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.instanceof(Array)
                done();
            });
        });

        it('Filters: date', function(done) {
            var moment = require('moment');
            date = moment().format('YYYYMMDD')

            request(common.url)
            .get("/manager/stats?date=" + date)
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.instanceof(Array)
                done();
            });
        });

        it('Filters: Invalid date', function(done) {
            request(common.url)
            .get("/manager/stats?date=2016/07/07")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(605);
                res.body.message.should.be.an.string;
                done();
            });
        });

        it('Filters: Invalid filter', function(done) {
            request(common.url)
            .get("/manager/stats?random")
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
            .get("/manager/stats?date=20160707&random")
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

    });  // GET/manager/stats

    describe('GET/manager/stats/hourly', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/manager/stats/hourly")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.have.properties(['averages', 'interactions']);
                done();
            });
        });

    });  // GET/manager/stats/hourly

    describe('GET/manager/stats/weekly', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/manager/stats/weekly")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                done();
            });
        });

    });  // GET/manager/stats/weekly

    /*
    describe('GET/manager/update-ruleset/backups', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/manager/update-ruleset/backups")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.instanceof(Array)
                done();
            });
        });

    });  // GET/manager/update-ruleset/backups
    */

    describe('GET/manager/logs', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/manager/logs")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                done();
            });
        });

        it('Pagination', function(done) {
            request(common.url)
            .get("/manager/logs?offset=0&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                done();
            });
        });

        it('Sort', function(done) {
            request(common.url)
            .get("/manager/logs?sort=+")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                done();
            });
        });

        it('Search', function(done) {
            request(common.url)
            .get("/manager/logs?search=info")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                done();
            });
        });

        it('Filters: type_log', function(done) {
            request(common.url)
            .get("/manager/logs?type_log=info")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                done();
            });
        });

        it('Filters: category', function(done) {
            request(common.url)
            .get("/manager/logs?category=ossec-testrule")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                done();
            });
        });

        it('Filters: type_log and category', function(done) {
            request(common.url)
            .get("/manager/logs?type_log=info&category=ossec-testrule")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                done();
            });
        });

        it('Filters: Invalid filter', function(done) {
            request(common.url)
            .get("/manager/logs?random")
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
            .get("/manager/logs?category=all&random")
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

    });  // GET/manager/logs

    describe('GET/manager/logs/summary', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/manager/logs/summary")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.have.properties(['ossec-testrule']);
                res.body.data['ossec-testrule'].should.have.properties(['info', 'all', 'error']);
                done();
            });
        });

    });  // PUT/manager/logs/summary

    /*
    describe('PUT/manager/start', function() {

        it('Request', function(done) {
            this.timeout(common.timeout);

            request(common.url)
            .put("/manager/start")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.instanceof(Array);
                done();
            });
        });

    });  // PUT/manager/start

    describe('PUT/manager/stop', function() {

        it('Request: Stop after start', function(done) {
            this.timeout(common.timeout);

            request(common.url)
            .put("/manager/stop")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.instanceof(Array);
                done();
            });
        });

    });  // PUT/manager/stop

    describe('PUT/manager/restart', function() {
        it('Request', function(done) {
            this.timeout(common.timeout);

            request(common.url)
            .put("/manager/restart")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.instanceof(Array);
                done();
            });
        });
    });  // PUT/manager/restart

    describe('PUT/manager/update-ruleset', function() {
        it('Request', function(done) {
            this.timeout(common.timeout);

            request(common.url)
            .put("/manager/update-ruleset")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.have.properties(['msg', 'need_restart', 'restarted']);
                done();
            });
        });

        it('Filters: Force', function(done) {
            this.timeout(common.timeout);

            request(common.url)
            .put("/manager/update-ruleset?force=yes")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.have.properties(['msg', 'need_restart', 'restarted', 'restart_status']);
                res.body.data['restart_status'].should.equal('success');
                done();
            });
        });

        it('Filters: Force & Type', function(done) {
            this.timeout(common.timeout);

            request(common.url)
            .put("/manager/update-ruleset?force=yes&type=rules")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.have.properties(['msg', 'need_restart', 'restarted', 'restart_status']);
                res.body.data['restart_status'].should.equal('success');
                done();
            });
        });

        it('Filters: Invalid filter', function(done) {
            request(common.url)
            .put("/manager/update-ruleset?random")
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
            .put("/manager/update-ruleset?force=yes&type=rules&random")
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

    });  // PUT/manager/update-ruleset

    describe('PUT/manager/update-ruleset/backups/:id', function() {
        var backup_id = 0;

        before(function(done) {
            request(common.url)
            .get("/manager/update-ruleset/backups")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.instanceof(Array);
                backup_id = res.body.data[0];
                done();
            });
        });

        it('Request', function(done) {
            this.timeout(common.timeout);

            request(common.url)
            .put("/manager/update-ruleset/backups/" + backup_id)
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.have.properties(['msg', 'need_restart', 'restarted']);
                res.body.data['msg'].should.equal('Backup successfully');
                done();
            });
        });

        it('Params: bad id', function(done) {
            request(common.url)
            .put("/manager/update-ruleset/backups/!hi")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(601);
                res.body.message.should.be.an.string;
                done();
            });
        });

        it('Errors: Invalid id', function(done) {
            request(common.url)
            .put("/manager/update-ruleset/backups/hi")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(500)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(2);
                res.body.message.should.be.an.string;
                done();
            });
        });

    });  // PUT/manager/update-ruleset/backups/:id
    */
});  // Manager
