var should = require('chai').should();
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

    it("should fail if username has changed", function() {
      var sut = new PasswordReboot("t9m0HLkdEyWQ6XN");
      var user = {
        username: "eve@hotmail.com"
      };
      var token = sut.createToken(user);
      user.username = "bob@hotmail.com";

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
  });

});
