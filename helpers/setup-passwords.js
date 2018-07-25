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
var readline = require('readline');

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

function update_user(name, password, cb){
    var user_data = { name: name, password: password };
    users.update_user(user_data, function (err) {
        if (!err)
            console.log(user_data.name + " updated. Password: " + password + "");
        else
            console.error("Can't update " + user_data.name + " password.");
        return cb(err);
    });
}

function auto() {
    console.log("Auto setting up passwords...")
    users.get_all_users_without_password(function (err, result) {
        if (!err && result) {
            result.forEach(function (user) {
                update_user(user.name, generate_rand_password(), function(){});
            });
        } else {
            console.error("Can't setup passwords.");
        }
    });
}

function parameters() {
    process.argv.slice(2).forEach(function (val, index, array) {
        user = val.split(":");
        update_user(user[0], user[1], function () { });
    });
}

function askCredentials(result, i) {

    var rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    if(!i) i = 0;
    
    if (i >= result.length) {
        rl.close(); 
        return;
    }
    const user = result[i]
    console.log("\nInsert password for " + user.name);
    rl.question("Password: ", function (password) {
        update_user(user.name, password, function(err) {
            return askCredentials(result, i + 1);
        });
        rl.close();  
    });

}

function interactive() {

    users.get_all_users_without_password(function (err, result) {
        if (!err && result) {
            askCredentials(result,0)
        } else {
            console.error("Can't setup passwords.");
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