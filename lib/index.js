var crypto = require("crypto");
var moment = require("moment");

var PasswordReboot = function(secret) {

  /**
   * The delimiter used to specify the boundary between the token expiration
   * timestamp and the token hash-based message authentication code.
   * @constant
   * @readonly
   * @type {String}
   */
  this._DELIMITER = ":";

  function createHmac(message) {
    return crypto
      .createHmac("sha1", secret)
      .update(message)
      .digest("hex");
  }

  this.createToken = function (user, minutesUntilExpiration) {
    var expirationTime = moment()
      .add({ minutes: minutesUntilExpiration || 20 })
      .unix();
    var hmac = createHmac(JSON.stringify(user) + expirationTime);
    return expirationTime + this._DELIMITER + hmac;
  };

  this.verifyToken = function verifyToken(user, token) {
    var parts = token.split(this._DELIMITER);
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
