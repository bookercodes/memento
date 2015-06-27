var crypto = require("crypto");
var moment = require("moment");

var PasswordReboot = function(secret) {

  var DELIMITER = ":";

  function createHmac(token) {
    return crypto
      .createHmac("sha1", secret)
      .update(token)
      .digest("hex");
  }

  this.createToken = function (user, minutesUntilExpiration) {
    var expirationTime = moment()
      .add({ minutes: minutesUntilExpiration || 20 })
      .unix();
    var hmac = createHmac(JSON.stringify(user) + expirationTime);
    return expirationTime + DELIMITER + hmac;
  };

  this.verifyToken = function verifyToken(user, token) {
    var parts = token.split(DELIMITER);
    var expirationTime = parts[0];
    var hmac = parts[1];
    var now = moment();
    var expired = now.isAfter(moment.unix(expirationTime));
    if (expired) {
      return false;
    }
    return createHmac(JSON.stringify(user) + expirationTime) === hmac;
  }

};

module.exports = PasswordReboot;
