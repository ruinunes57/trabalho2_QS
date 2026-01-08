"use strict";
const mysql = require("mysql");
const options = require("./connection-options.json");


//============================================================= Logout
module.exports.logout = (request, response) => {
    request.session.User = undefined;
    response.sendStatus(200);
}
