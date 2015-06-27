var should = require('chai').should();
var sinon = require("sinon");
var moment = require("moment");

var PasswordReboot = require("../lib/index");

describe("PasswordReboot", function() {

  describe("createToken", function() {
    it("should return a token", function() {
      var sut = new PasswordReboot("t9m0HLkdEyWQ6XN");
      var user = {
        username: "bob@hotmail.com"
      };

      var actual = sut.createToken(user);

      should.exist(actual);
    });
  });

  describe("verifyToken", function() {
    it("should succeed if token is correct", function() {
      var sut = new PasswordReboot("t9m0HLkdEyWQ6XN");
      var user = {
        username: "bob@hotmail.com"
      };
      var token = sut.createToken(user);

      var actual = sut.verifyToken(user, token);

      actual.should.equal(true);
    });

    it("should fail if username changes", function() {
      var sut = new PasswordReboot("t9m0HLkdEyWQ6XN");
      var user = {
        username: "eve@hotmail.com"
      };
      var token = sut.createToken(user);
      user.username = "bob@hotmail.com";

      var actual = sut.verifyToken(user, token);

      actual.should.equal(false);
    });

    it("should fail if any user property changes", function() {
      var sut = new PasswordReboot("t9m0HLkdEyWQ6XN");
      var user = {
        username: "eve@hotmail.com",
        salt: "23423412341233"
      };
      var token = sut.createToken(user);
      user.salt = "8888888";

      var actual = sut.verifyToken(user, token);

      actual.should.equal(false);
    });

    it("should fail if token has changed", function() {
      var passwordReboot = new PasswordReboot("t9m0HLkdEyWQ6XN");
      var user = {
        username: "bob@hotmail.com"
      };
      var token = passwordReboot.createToken(user);
      var sut = new PasswordReboot("0qNR4pkBYA");

      var actual = sut.verifyToken(user, token);

      actual.should.equal(false);
    });

    it("should fail if token has been tampered with", function() {
      var sut = new PasswordReboot("t9m0HLkdEyWQ6XN");
      var user = {
        username: "bob@hotmail.com"
      };

      var actual = sut.verifyToken(user, "some invalid token...");

      actual.should.equal(false);
    });

    it("should fail if token has expired", function() {
      var sut = new PasswordReboot("t9m0HLkdEyWQ6XN");
      var user = {
        username: "bob@hotmail.com"
      };
      var token = sut.createToken(user);
      var clock = sinon.useFakeTimers(moment().add({ minutes: 20 }).valueOf());

      var actual = sut.verifyToken(user, token);

      actual.should.equal(false);

      clock.reset();
    });

    it("should fail if token has expired custom minutes until expiration", function() {
      var sut = new PasswordReboot("t9m0HLkdEyWQ6XN");
      var user = {
        username: "bob@hotmail.com"
      };
      var MINUTES_UNTIL_EXPIRATION = 10;
      var token = sut.createToken(user, MINUTES_UNTIL_EXPIRATION);
      var clock = sinon.useFakeTimers(moment().add({ minutes: MINUTES_UNTIL_EXPIRATION }).valueOf());

      var actual = sut.verifyToken(user, token);

      actual.should.equal(false);

      clock.reset();
    });


    it("should succeed if token has not expired custom minutes until expiration", function() {
      var sut = new PasswordReboot("t9m0HLkdEyWQ6XN");
      var user = {
        username: "bob@hotmail.com"
      };
      var MINUTES_UNTIL_EXPIRATION = 10;
      var token = sut.createToken(user, MINUTES_UNTIL_EXPIRATION);

      var actual = sut.verifyToken(user, token);

      actual.should.equal(true);
    });

    it("should fail if expiration timestamp has been tampered with", function() {
      var sut = new PasswordReboot("t9m0HLkdEyWQ6XN");
      var user = {
        username: "bob@hotmail.com"
      };
      var token = sut.createToken(user);
      var parts = token.split(":");
      var hmac = parts[1];
      var expirationTime = Number.MAX_VALUE;
      token = expirationTime + ":" + hmac;

      var actual = sut.verifyToken(user, token);

      actual.should.equal(false);
    });


  });

});
