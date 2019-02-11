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

                res.body.data.should.have.properties(['wazuh-modulesd', 'ossec-authd', 'ossec-monitord', 'ossec-logcollector', 'ossec-execd', 'ossec-remoted', 'ossec-syscheckd', 'ossec-analysisd', 'ossec-maild']);
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
                res.body.data.should.have.properties(['path', 'compilation_date', 'version', 'type']);
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
                res.body.data.should.have.properties(['global', 'ruleset', 'syscheck', 'rootcheck', 'remote', 'localfile']);
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
            .get("/manager/configuration?section=ruleset")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.have.properties(['decoder_dir', 'rule_dir', 'rule_exclude', 'list']);
                res.body.data.rule_dir.should.be.instanceof(Array)
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
            .get("/manager/configuration?section=ruleset&field=rule_dir")
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
            .get("/manager/configuration?section=ruleset&field=includedd")
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
            .get("/manager/configuration?section=ruleset&field=rule_dir&random")
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

    });  // GET/manager/configuration

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

    describe('GET/manager/stats/analysisd', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/manager/stats/analysisd")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;

                res.body.data.should.have.properties(['archives_queue_size',
                'events_dropped', 'alerts_queue_size', 'rule_matching_queue_usage',
                'events_processed', 'event_queue_usage', 'events_edps',
                'hostinfo_events_decoded', 'syscollector_events_decoded',
                'rootcheck_edps', 'firewall_queue_usage', 'alerts_queue_usage',
                'firewall_queue_size', 'alerts_written', 'firewall_written',
                'syscheck_queue_size', 'events_received', 'rootcheck_queue_usage',
                'rootcheck_events_decoded', 'rootcheck_queue_size', 'syscheck_edps',
                'fts_written', 'syscheck_queue_usage', 'other_events_edps',
                'statistical_queue_usage', 'hostinfo_edps', 'hostinfo_queue_usage',
                'syscheck_events_decoded', 'syscheck_events_decoded', 'archives_queue_usage',
                'statistical_queue_size', 'total_events_decoded', 'hostinfo_queue_size',
                'syscollector_queue_size', 'rule_matching_queue_size',
                'other_events_decoded', 'event_queue_size', 'syscollector_edps']);
                done();
            });
        });

    });  // GET/manager/stats/analysisd

    describe('GET/manager/stats/remoted', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/manager/stats/remoted")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.have.properties(['discarded_count',
                'msg_sent', 'queue_size', 'ctrl_msg_count', 'evt_count',
                'tcp_sessions', 'total_queue_size']);
                done();
            });
        });

    });  // GET/manager/stats/remoted

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

        it('Retrieve all elements with limit=0', function(done) {
            request(common.url)
            .get("/manager/logs?limit=0")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1406);
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

        it('SortField', function(done) {
            request(common.url)
            .get("/manager/logs?sort=+level")
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
            .get("/manager/logs?category=ossec-monitord")
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
            .get("/manager/logs?type_log=info&category=ossec-analysisd")
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

                res.body.data.should.have.properties(['ossec-monitord']);
                res.body.data['ossec-monitord'].should.have.properties(['info', 'all', 'error']);

                done();
            });
        });

    });  // GET/manager/logs/summary

    describe('PUT/manager/restart', function() {

        it('Request', function(done) {
            request(common.url)
            .put("/manager/restart")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.string;

                done();
            });
        });

    });  // PUT/manager/restart

});  // Manager
