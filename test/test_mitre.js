/**
 * API RESTful for OSSEC
 * Copyright (C) 2015-2019 Wazuh, Inc.All rights reserved.
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


describe('Mitre', function() {

    keys = ['id', 'json', 'platforms', 'phases']

    describe('GET/sca/:agent_id', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/mitre")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Pagination: limit = 1', function(done) {
            request(common.url)
            .get("/mitre?offset=4&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Pagination: limit = 5', function(done) {
            request(common.url)
            .get("/mitre?offset=10&limit=5")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(5);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Pagination: limit = 10', function(done) {
            request(common.url)
            .get("/mitre?offset=10&limit=10")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(10);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Pagination: limit > 10', function(done) {
            request(common.url)
            .get("/mitre?offset=10&limit=15")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(10);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Retrieve all elements with limit=0', function(done) {
            request(common.url)
            .get("/mitre?limit=0")
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

        it('Filters: attack', function(done) {
            request(common.url)
            .get("/mitre?attack=T1101")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: attack (request returns 0 items)', function(done) {
            request(common.url)
            .get("/mitre?attack=T99")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(0);
                done();
            });
        });

        it('Filters: phase=initial access', function(done) {
            request(common.url)
            .get("/mitre?phase=initial%20access")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: phase=persistence', function(done) {
            request(common.url)
            .get("/mitre?phase=persistence")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: phase (request returns 0 items)', function(done) {
            request(common.url)
            .get("/mitre?phase=wrong%20phase")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(0);
                done();
            });
        });

        it('Filters: platform=linux', function(done) {
            request(common.url)
            .get("/mitre?platform=linux")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: platform=macos', function(done) {
            request(common.url)
            .get("/mitre?platform=macos")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: platform=windows', function(done) {
            request(common.url)
            .get("/mitre?platform=windows")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: platform=windows,phase=persistence', function(done) {
            request(common.url)
            .get("/mitre?platform=windows&phase=persistence")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: platform=linux,phase=execution', function(done) {
            request(common.url)
            .get("/mitre?platform=linux&phase=execution")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: platform=macos,phase=impact', function(done) {
            request(common.url)
            .get("/mitre?platform=linux&phase=impact")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: platform (request returns 0 items)', function(done) {
            request(common.url)
            .get("/mitre?platform=hpux")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(0);
                done();
            });
        });

        it('Filters: q=attack=T1015', function(done) {
            request(common.url)
            .get("/mitre?q=attack=T1015")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: q=platform=linux', function(done) {
            request(common.url)
            .get("/mitre?q=platform=linux&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: q=phase=execution', function(done) {
            request(common.url)
            .get("/mitre?q=phase=execution&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: q (request returns 0 items)', function(done) {
            request(common.url)
            .get("/mitre?q=id=T1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(0);
                done();
            });
        });

        it('Filters: q (wrong query 1)', function(done) {
            request(common.url)
            .get("/mitre?q=phase_names=impact")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1408);
                done();
            });
        });

        it('Filters: q (wrong query 2)', function(done) {
            request(common.url)
            .get("/mitre?q=system=linux")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1408);
                done();
            });
        });

        it('Filters: q (wrong query 3)', function(done) {
            request(common.url)
            .get("/mitre?q=attack_id=T1100")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1408);
                done();
            });
        });

    });  // GET /mitre

});  // Mitre
