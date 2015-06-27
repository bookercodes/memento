var crypto = require("crypto");

var PasswordReboot = function(secret) {
  function signToken(token) {
    return crypto
      .createHmac("sha1", secret)
      .update(token)
      .digest("hex");
  }

  this.createToken = function createToken(user) {
    return signToken(JSON.stringify(user));
  };

  this.verifyToken = function verifyToken(user, token) {
    return signToken(JSON.stringify(user)) === token;
  }
};

module.exports = PasswordReboot;
