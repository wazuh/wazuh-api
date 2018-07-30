#!/usr/bin/env node

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

var users = require('./users');
var crypto = require('crypto'); 
var read = require("read")

function generate_rand_password() {
    var randomValueHex = function(len){
        return (crypto.randomBytes(Math.ceil(len / 2))
            .toString('hex')
            .slice(0, len).toUpperCase());   
    } 
    return randomValueHex(10) + 
    crypto.createHash('sha1').update(randomValueHex(10)).digest('hex').slice(0, 10) +
    randomValueHex(10);
}

function update_user(name, password, show_pass, cb){
    var user_data = { name: name, password: password };
    users.update_user(user_data, function (err) {
        if (!err){
            if (show_pass)
                msg = user_data.name + " updated. Password: " + password + "";
            else
                msg = user_data.name + " updated.";
            console.log(msg);
        } else
            console.error("Can't update " + user_data.name + " password.");
        return cb(err);
    });
}

function auto() {
    console.log("Auto setting up passwords...")
    users.get_all_users_without_password(function (err, result) {
        if (!err && result) {
            result.forEach(function (user) {
                update_user(user.name, generate_rand_password(), true, function(){});
            });
        } else {
            console.error("Can't setup passwords.");
        }
    });
}

function parameters() {
    process.argv.slice(2).forEach(function (val, index, array) {
        user = val.split(":");
        update_user(user[0], user[1], false, function () { });
    });
}

function askCredentials(result, i) {

    if(!i) i = 0;
    if (i >= result.length) {
        return;
    }
    const user = result[i]

    console.log("\nInsert password for " + user.name);
    read({ prompt: "Password: ", default: "", silent: true }, function (er, pass) {
        read({ prompt: "Password again: ", default: "", silent: true }, function (er, pass2) {
            if (!er && pass && pass.length > 0 && pass === pass2) {
                update_user(user.name, pass, false, function (err) {
                    return askCredentials(result, i + 1);
                });
            } else {
                console.error("Invalid password for " + user.name + ". Please, try again.")
                return askCredentials(result, i);
            }
        })
    })
}

function interactive() {
    users.get_all_users_without_password(function (err, result) {
        if (!err && result && result.length > 0) {
            askCredentials(result,0)
        } else {
            if (!result.length > 0)
                msg = "All users are set up.";
            else
                msg = "Can't setup passwords.";
            console.error(msg);
        }
    });
}


if (process.argv.length <= 2 || (process.argv.length == 3 && process.argv[2] == "auto")){
    auto();
} else if (process.argv.length > 2 && process.argv[2] == "interactive") {
    interactive();
} else {
    parameters();
}
