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

describe('Syscollector', function() {


  describe('GET/syscollector/:agent_id/os', function() {

    var expected_hostname = "";
    var expected_architecture = "";
    before(function(done) {
        request(common.url)
        .get("/agents/001")
        .auth(common.credentials.user, common.credentials.password)
        .expect("Content-type",/json/)
        .expect(200)
        .end(function(err,res){
            if (err) return done(err);
            res.body.should.have.properties(['error', 'data']);
            res.body.error.should.equal(0);
            res.body.data.should.have.properties(['os', 'manager_host']);
            res.body.data.os.should.have.properties(['arch', 'platform']);
            expected_hostname = res.body.data.manager_host;
            expected_architecture = res.body.data.os.arch;
            done();
        });
      });

      it('Request', function(done) {
          request(common.url)
          .get("/syscollector/001/os")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.should.be.an.array;
              res.body.data.should.have.properties(['sysname', 'os', 'scan', 'hostname', 'version', 'architecture', 'release']);
              res.body.data.os.should.have.properties(['name','version']);
              res.body.data.scan.should.have.properties(['id', 'time']);
              res.body.data.hostname.should.be.equal(expected_hostname);
              res.body.data.architecture.should.be.equal(expected_architecture);
              done();
          });
      });

      it('Selector', function(done) {
          request(common.url)
          .get("/syscollector/001/os?select=os_version,sysname,release")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.should.have.properties(['os_version', 'sysname', 'release']);
              done();
          });
      });

      it('Not allowed selector', function(done) {
          request(common.url)
          .get("/syscollector/001/os?select=wrongParam")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'message']);
              res.body.error.should.equal(1724);
              done();
          });
      });

  });  // GET/syscollector/:agent_id/os


  describe('GET/syscollector/:agent_id/hardware', function() {

      it('Request', function(done) {
          request(common.url)
          .get("/syscollector/001/hardware")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.should.be.an.array;
              res.body.data.should.have.properties(['ram', 'scan', 'board_serial', 'cpu']);
              res.body.data.ram.should.have.properties(['free', 'total']);
              res.body.data.scan.should.have.properties(['id', 'time']);
              res.body.data.cpu.should.have.properties(['name', 'cores', 'mhz']);
              done();
          });
      });

      it('Selector', function(done) {
          request(common.url)
          .get("/syscollector/001/hardware?select=ram_free,board_serial,cpu_name,ram_total")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.should.have.properties(['board_serial', 'ram', 'cpu_name']);
              res.body.data.ram.should.have.properties(['free', 'total']);
              done();
          });
      });

      it('Not allowed selector', function(done) {
          request(common.url)
          .get("/syscollector/001/hardware?select=wrongParam")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'message']);
              res.body.error.should.equal(1724);
              done();
          });
      });

  });  // GET/syscollector/:agent_id/os


  describe('GET/syscollector/:agent_id/packages', function() {

      it('Request', function(done) {
          request(common.url)
          .get("/syscollector/001/packages")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['vendor', 'description', 'format', 'version', 'architecture', 'name', 'scan_id']);
              done();
          });
      });

      it('Selector', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?select=scan_id,description,architecture")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['description', 'architecture', 'scan_id']);
              done();
          });
      });

      it('Not allowed selector', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?select=wrongParam")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'message']);
              res.body.error.should.equal(1724);
              done();
          });
      });

      it('Pagination', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?offset=0&limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['vendor', 'description', 'format', 'version', 'architecture', 'name', 'scan_id']);
              done();
          });
      });

      it('Wrong limit', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?offset=0&limit=1a")
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

      it('Sort -', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?sort=-name&limit=2")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(2);
              res.body.data.items[0].should.have.properties(['name']);
              res.body.data.items[1].should.have.properties(['name']);
              res.body.data.items[0].name.should.not.be.greaterThan(res.body.data.items[1].name);
              done();
          });
      });

      it('Sort +', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?sort=+name&limit=2")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(2);
              res.body.data.items[0].should.have.properties(['name']);
              res.body.data.items[1].should.have.properties(['name']);
              res.body.data.items[1].name.should.not.be.greaterThan(res.body.data.items[0].name);
              done();
          });
      });

      it('Wrong Sort', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?sort=-wrongParameter")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'message']);
              res.body.error.should.equal(1403);
              done();
          });
      });

    var expected_name = "";
    before(function(done) {
        request(common.url)
        .get("/syscollector/001/packages?limit=1")
        .auth(common.credentials.user, common.credentials.password)
        .expect("Content-type",/json/)
        .expect(200)
        .end(function(err,res){
            if (err) return done(err);
            res.body.should.have.properties(['error', 'data']);
            res.body.error.should.equal(0);
            res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
            res.body.data.items[0].should.have.properties(['name']);
            expected_name = res.body.data.items[0].name;
            done();
        });
      });

      it('Search', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?search="+expected_name)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['scan_id', 'vendor', 'description', 'format', 'scan_time', 'version', 'architecture', 'name']);
              res.body.data.items[0].name.should.be.equal(expected_name);
              done();
          });
      });

      var expected_vendor = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/001/packages?limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['vendor']);
              expected_vendor = res.body.data.items[0].vendor;
              done();
          });
      });

      it('Filter vendor', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?vendor=" + expected_vendor)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['vendor']);
              res.body.data.items[0].vendor.should.be.equal(expected_vendor);
              done();
          });
      });

      var expected_filter_name = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/001/packages?limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['name']);
              expected_filter_name = res.body.data.items[0].name;
              done();
          });
      });

      it('Filter name', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?name=" + expected_filter_name)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['name']);
              res.body.data.items[0].name.should.be.equal(expected_filter_name);
              done();
          });
      });

      var expected_architecture = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/001/packages?limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['architecture']);
              expected_architecture = res.body.data.items[0].architecture;
              done();
          });
      });

      it('Filter architecture', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?architecture=" + expected_architecture)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['architecture']);
              res.body.data.items[0].architecture.should.be.equal(expected_architecture);
              done();
          });
      });

      var expected_format = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/001/packages?limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['format']);
              expected_format = res.body.data.items[0].format;
              done();
          });
      });

      it('Filter format', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?format=" + expected_format)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['format']);
              res.body.data.items[0].format.should.be.equal(expected_format);
              done();
          });
      });

      it('Wrong filter', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?wrongFilter=value")
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

  });  // GET/syscollector/:agent_id/packages


  describe('GET/syscollector/packages', function() {

      it('Request', function(done) {
          request(common.url)
          .get("/syscollector/packages")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['scan_id', 'agent_id', 'vendor', 'description', 'format', 'scan_time', 'version', 'architecture', 'name']);
              done();
          });
      });

      it('Selector', function(done) {
          request(common.url)
          .get("/syscollector/packages?select=scan_id,description,scan_time,architecture")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['scan_id', 'description', 'scan_time', 'architecture']);
              done();
          });
      });

      it('Not allowed selector', function(done) {
          request(common.url)
          .get("/syscollector/packages?select=wrongParam")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'message']);
              res.body.error.should.equal(1724);
              done();
          });
      });

      it('Pagination', function(done) {
          request(common.url)
          .get("/syscollector/packages?offset=0&limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['scan_id', 'agent_id', 'vendor', 'description', 'format', 'scan_time', 'version', 'architecture', 'name']);
              done();
          });
      });

      it('Wrong limit', function(done) {
          request(common.url)
          .get("/syscollector/packages?offset=0&limit=1a")
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

      it('Sort -', function(done) {
          request(common.url)
          .get("/syscollector/packages?sort=-name&limit=2")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(2);
              res.body.data.items[0].should.have.properties(['name']);
              res.body.data.items[1].should.have.properties(['name']);
              res.body.data.items[0].name.should.not.be.greaterThan(res.body.data.items[1].name);
              done();
          });
      });

      it('Sort +', function(done) {
          request(common.url)
          .get("/syscollector/packages?sort=+name&limit=2")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(2);
              res.body.data.items[0].should.have.properties(['name']);
              res.body.data.items[1].should.have.properties(['name']);
              res.body.data.items[1].name.should.not.be.greaterThan(res.body.data.items[0].name);
              done();
          });
      });

      it('Wrong Sort', function(done) {
          request(common.url)
          .get("/syscollector/packages?sort=-wrongParameter")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'message']);
              res.body.error.should.equal(1403);
              done();
          });
      });

    var expected_name = "";
    before(function(done) {
        request(common.url)
        .get("/syscollector/packages?limit=1")
        .auth(common.credentials.user, common.credentials.password)
        .expect("Content-type",/json/)
        .expect(200)
        .end(function(err,res){
            if (err) return done(err);
            res.body.should.have.properties(['error', 'data']);
            res.body.error.should.equal(0);
            res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
            res.body.data.items[0].should.have.properties(['name']);
            expected_name = res.body.data.items[0].name;
            done();
        });
      });

      it('Search', function(done) {
          request(common.url)
          .get("/syscollector/packages?search="+expected_name)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['scan_id', 'vendor', 'description', 'format', 'scan_time', 'version', 'architecture', 'name']);
              res.body.data.items[0].name.should.be.equal(expected_name);
              done();
          });
      });

      var expected_vendor = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/packages?limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['vendor']);
              expected_vendor = res.body.data.items[0].vendor;
              done();
          });
      });

      it('Filter vendor', function(done) {
          request(common.url)
          .get("/syscollector/packages?vendor=" + expected_vendor)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['vendor']);
              res.body.data.items[0].vendor.should.be.equal(expected_vendor);
              done();
          });
      });

      var expected_filter_name = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/packages?limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['name']);
              expected_filter_name = res.body.data.items[0].name;
              done();
          });
      });

      it('Filter name', function(done) {
          request(common.url)
          .get("/syscollector/packages?name=" + expected_filter_name)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['name']);
              res.body.data.items[0].name.should.be.equal(expected_filter_name);
              done();
          });
      });

      var expected_architecture = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/packages?limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['architecture']);
              expected_architecture = res.body.data.items[0].architecture;
              done();
          });
      });

      it('Filter architecture', function(done) {
          request(common.url)
          .get("/syscollector/packages?architecture=" + expected_architecture)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['architecture']);
              res.body.data.items[0].architecture.should.be.equal(expected_architecture);
              done();
          });
      });

      var expected_format = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/packages?limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['format']);
              expected_format = res.body.data.items[0].format;
              done();
          });
      });

      it('Filter format', function(done) {
          request(common.url)
          .get("/syscollector/packages?format=" + expected_format)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['format']);
              res.body.data.items[0].format.should.be.equal(expected_format);
              done();
          });
      });

      it('Wrong filter', function(done) {
          request(common.url)
          .get("/syscollector/packages?wrongFilter=value")
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

  });  // GET/syscollector/packages



  describe('GET/syscollector/os', function() {

    it('Request', function(done) {
        request(common.url)
        .get("/syscollector/os")
        .auth(common.credentials.user, common.credentials.password)
        .expect("Content-type",/json/)
        .expect(200)
        .end(function(err,res){
            if (err) return done(err);

            res.body.should.have.properties(['error', 'data']);

            res.body.error.should.equal(0);
            res.body.data.totalItems.should.be.above(0);
            res.body.data.items.should.be.instanceof(Array)
            res.body.data.items[0].should.have.properties(['sysname', 'hostname', 'version', 'architecture', 'release', 'os_name',  'os_version',  'scan_id',  'scan_time']);
            done();
        });
    });

    it('Selector', function(done) {
        request(common.url)
        .get("/syscollector/os?select=sysname,version,release,os_version")
        .auth(common.credentials.user, common.credentials.password)
        .expect("Content-type",/json/)
        .expect(200)
        .end(function(err,res){
            if (err) return done(err);

            res.body.should.have.properties(['error', 'data']);

            res.body.error.should.equal(0);
            res.body.data.totalItems.should.be.above(0);
            res.body.data.items.should.be.instanceof(Array)
            res.body.data.items[0].should.have.properties(['sysname', 'version', 'release', 'os_version']);
            done();
        });
    });

    it('Not allowed selector', function(done) {
        request(common.url)
        .get("/syscollector/os?select=wrongParam")
        .auth(common.credentials.user, common.credentials.password)
        .expect("Content-type",/json/)
        .expect(200)
        .end(function(err,res){
            if (err) return done(err);
            res.body.should.have.properties(['error', 'message']);
            res.body.error.should.equal(1724);
            done();
        });
    });

    it('Pagination', function(done) {
        request(common.url)
        .get("/syscollector/os?offset=0&limit=1")
        .auth(common.credentials.user, common.credentials.password)
        .expect("Content-type",/json/)
        .expect(200)
        .end(function(err,res){
            if (err) return done(err);

            res.body.should.have.properties(['error', 'data']);

            res.body.error.should.equal(0);
            res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
            res.body.data.items[0].should.have.properties(['sysname', 'hostname', 'version', 'architecture', 'release', 'os_name',  'os_version',  'scan_id',  'scan_time']);
            done();
        });
    });

    it('Wrong limit', function(done) {
        request(common.url)
        .get("/syscollector/os?offset=0&limit=1a")
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

    var expected_name = "";
    before(function(done) {
        request(common.url)
        .get("/syscollector/os?limit=1")
        .auth(common.credentials.user, common.credentials.password)
        .expect("Content-type",/json/)
        .expect(200)
        .end(function(err,res){
            if (err) return done(err);
            res.body.should.have.properties(['error', 'data']);
            res.body.error.should.equal(0);
            res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
            res.body.data.items[0].should.have.properties(['sysname']);
            expected_name = res.body.data.items[0].sysname;
            done();
        });
      });

      it('Search', function(done) {
          request(common.url)
          .get("/syscollector/os?search="+expected_name)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['sysname', 'hostname', 'version', 'architecture', 'release', 'os_name',  'os_version',  'scan_id',  'scan_time']);
              res.body.data.items[0].sysname.should.be.equal(expected_name);
              done();
          });
      });

      it('Wrong filter', function(done) {
          request(common.url)
          .get("/syscollector/os?wrongFilter=value")
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

      var expected_architecture = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/os?limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['architecture']);
              expected_architecture= res.body.data.items[0].architecture;
              done();
          });
      });

      it('Filter architecture', function(done) {
          request(common.url)
          .get("/syscollector/os?architecture=" + expected_architecture)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['architecture']);
              res.body.data.items[0].architecture.should.be.equal(expected_architecture);
              done();
          });
      });

      var expected_os_name = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/001/os")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.should.have.properties(['os']);
              res.body.data.os.should.have.properties(['name']);
              expected_os_name= res.body.data.os.name;
              done();
          });
      });

      it('Filter os_name', function(done) {
          request(common.url)
          .get("/syscollector/os?os_name=" + expected_os_name)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['os_name']);
              res.body.data.items[0].os_name.should.be.equal(expected_os_name);
              done();
          });
      });

      var expected_os_version = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/os?limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['os_version']);
              expected_os_version= res.body.data.items[0].os_version;
              done();
          });
      });

      it('Filter os_version', function(done) {
          request(common.url)
          .get("/syscollector/os?os_version=" + expected_os_version.replace(/\s/g, '%20'))
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['os_version']);
              res.body.data.items[0].os_version.should.be.equal(expected_os_version);
              done();
          });
      });

      var expected_version = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/os?limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['version']);
              expected_version= res.body.data.items[0].version;
              done();
          });
      });

      it('Filter version', function(done) {
          request(common.url)
          .get("/syscollector/os?version=" + expected_version.replace(/\s/g, '%20'))
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['version']);
              res.body.data.items[0].version.should.be.equal(expected_version);
              done();
          });
      });

      var expected_release = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/os?limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['release']);
              expected_release= res.body.data.items[0].release;
              done();
          });
      });

      it('Filter release', function(done) {
          request(common.url)
          .get("/syscollector/os?release=" + expected_release)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['release']);
              res.body.data.items[0].release.should.be.equal(expected_release);
              done();
          });
      });

  });  // GET/syscollector/os

  describe('GET/syscollector/hardware', function() {

    it('Request', function(done) {
        request(common.url)
        .get("/syscollector/hardware")
        .auth(common.credentials.user, common.credentials.password)
        .expect("Content-type",/json/)
        .expect(200)
        .end(function(err,res){
            if (err) return done(err);

            res.body.should.have.properties(['error', 'data']);

            res.body.error.should.equal(0);
            res.body.data.totalItems.should.be.above(0);
            res.body.data.items.should.be.instanceof(Array)
            res.body.data.items[0].should.have.properties(['ram_free', 'scan_id', 'board_serial', 'scan_time', 'cpu_name', 'cpu_cores', 'agent_id', 'ram_total', 'cpu_mhz']);
            done();
        });
    });

    it('Selector', function(done) {
        request(common.url)
        .get("/syscollector/hardware?select=ram_free,board_serial,cpu_name,agent_id,cpu_mhz")
        .auth(common.credentials.user, common.credentials.password)
        .expect("Content-type",/json/)
        .expect(200)
        .end(function(err,res){
            if (err) return done(err);

            res.body.should.have.properties(['error', 'data']);

            res.body.error.should.equal(0);
            res.body.data.totalItems.should.be.above(0);
            res.body.data.items.should.be.instanceof(Array)
            res.body.data.items[0].should.have.properties(['ram_free', 'board_serial', 'cpu_name', 'agent_id', 'cpu_mhz']);
            done();
        });
    });

    it('Not allowed selector', function(done) {
        request(common.url)
        .get("/syscollector/hardware?select=wrongParam")
        .auth(common.credentials.user, common.credentials.password)
        .expect("Content-type",/json/)
        .expect(200)
        .end(function(err,res){
            if (err) return done(err);
            res.body.should.have.properties(['error', 'message']);
            res.body.error.should.equal(1724);
            done();
        });
    });

    it('Pagination', function(done) {
        request(common.url)
        .get("/syscollector/hardware?offset=0&limit=1")
        .auth(common.credentials.user, common.credentials.password)
        .expect("Content-type",/json/)
        .expect(200)
        .end(function(err,res){
            if (err) return done(err);

            res.body.should.have.properties(['error', 'data']);

            res.body.error.should.equal(0);
            res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
            res.body.data.items[0].should.have.properties(['ram_free', 'scan_id', 'board_serial', 'scan_time', 'cpu_name', 'cpu_cores', 'agent_id', 'ram_total', 'cpu_mhz']);
            done();
        });
    });

    it('Wrong limit', function(done) {
        request(common.url)
        .get("/syscollector/hardware?offset=0&limit=1a")
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

    var expected_ram_free = "";
    before(function(done) {
        request(common.url)
        .get("/syscollector/hardware?limit=1")
        .auth(common.credentials.user, common.credentials.password)
        .expect("Content-type",/json/)
        .expect(200)
        .end(function(err,res){
            if (err) return done(err);
            res.body.should.have.properties(['error', 'data']);
            res.body.error.should.equal(0);
            res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
            res.body.data.items[0].should.have.properties(['ram_free']);
            expected_ram_free = res.body.data.items[0].ram_free;
            done();
        });
      });

      it('Search', function(done) {
          request(common.url)
          .get("/syscollector/hardware?search="+expected_ram_free)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['ram_free', 'scan_id', 'board_serial', 'scan_time', 'cpu_name', 'cpu_cores', 'agent_id', 'ram_total', 'cpu_mhz']);
              res.body.data.items[0].ram_free.should.be.equal(expected_ram_free);
              done();
          });
      });

      it('Wrong filter', function(done) {
          request(common.url)
          .get("/syscollector/hardware?wrongFilter=value")
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

      it('Wrong Sort', function(done) {
          request(common.url)
          .get("/syscollector/hardware?sort=-wrongParameter")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'message']);
              res.body.error.should.equal(1403);
              done();
          });
      });

      it('Filter ram_free', function(done) {
          request(common.url)
          .get("/syscollector/hardware?ram_free=" + expected_ram_free)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['ram_free']);
              res.body.data.items[0].ram_free.should.be.equal(expected_ram_free);
              done();
          });
      });

      var expected_ram_total = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/001/hardware")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.should.have.properties(['ram']);
              res.body.data.ram.should.have.properties(['total']);
              expected_ram_total = res.body.data.ram.total;
              done();
          });
      });

      it('Filter ram_total', function(done) {
          request(common.url)
          .get("/syscollector/hardware?ram_total=" + expected_ram_total)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['ram_total']);
              res.body.data.items[0].ram_total.should.be.equal(expected_ram_total);
              done();
          });
      });

      var expected_cpu_cores = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/001/hardware")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.should.have.properties(['cpu']);
              res.body.data.cpu.should.have.properties(['cores']);
              expected_cpu_cores = res.body.data.cpu.cores;
              done();
          });
      });

      it('Filter cpu_cores', function(done) {
          request(common.url)
          .get("/syscollector/hardware?cpu_cores=" + expected_cpu_cores)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['cpu_cores']);
              res.body.data.items[0].cpu_cores.should.be.equal(expected_cpu_cores);
              done();
          });
      });

      var expected_cpu_mhz = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/001/hardware")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.should.have.properties(['cpu']);
              res.body.data.cpu.should.have.properties(['mhz']);
              expected_cpu_mhz = res.body.data.cpu.mhz;
              done();
          });
      });

      it('Filter cpu_mhz', function(done) {
          request(common.url)
          .get("/syscollector/hardware?cpu_mhz=" + expected_cpu_mhz)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['cpu_mhz']);
              res.body.data.items[0].cpu_mhz.should.be.equal(expected_cpu_mhz);
              done();
          });
      });

      var expected_cpu_name = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/001/hardware")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.should.have.properties(['cpu']);
              res.body.data.cpu.should.have.properties(['name']);
              expected_cpu_name = res.body.data.cpu.name;
              done();
          });
      });

      it('Filter cpu_name', function(done) {
          request(common.url)
          .get("/syscollector/hardware?cpu_name=" + expected_cpu_name.replace(/\s/g, '%20'))
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['cpu_name']);
              res.body.data.items[0].cpu_name.should.be.equal(expected_cpu_name);
              done();
          });
      });

      var expected_board_serial = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/001/hardware")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.should.have.properties(['board_serial']);
              expected_board_serial = res.body.data.board_serial;
              done();
          });
      });

      it('Filter board_serial', function(done) {
          request(common.url)
          .get("/syscollector/hardware?board_serial=" + expected_board_serial)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['board_serial']);
              res.body.data.items[0].board_serial.should.be.equal(expected_board_serial);
              done();
          });
      });

  });  // GET/syscollector/hardware

});  // Syscollector
