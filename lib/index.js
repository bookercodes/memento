var crypto = require("crypto");

var PasswordReboot = function(secret) {
  function signToken(token) {
    return crypto
      .createHmac("sha1", secret)
      .update(token)
      .digest("hex");
  }

  this.createToken = function createToken(user) {
    return signToken(user.username);
  };

  this.verifyToken = function verifyToken(user, token) {
    return signToken(user.username) === token;
  }
};

module.exports = PasswordReboot;
