var crypto = require("crypto");
var moment = require("moment");

var PasswordReboot = function(secret) {
  var DELIMITER = ":";

  function signToken(token) {
    return crypto
      .createHmac("sha1", secret)
      .update(token)
      .digest("hex");
  }

  this.createToken = function createToken(user) {
    var expirationTime = moment().add({ minutes: 20 }).unix();
    var token = signToken(JSON.stringify(user));
    return expirationTime + ":" + token;
  };

  this.verifyToken = function verifyToken(user, token) {

    var parts = token.split(DELIMITER);
    var expirationTime = parts[0];
    var token = parts[1];

    var now = moment();
    var then = moment.unix(expirationTime);
    var expired = now.isAfter(then)
    if (expired) {
      return false;
    }

    return signToken(JSON.stringify(user)) === token;
  }
};

module.exports = PasswordReboot;
