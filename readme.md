*Memento is a module that handles the creation and verification of ephemeral tokens. It is really useful for password reset and email activation features.*

##Installation

Memento is available on [npm](https://www.npmjs.com/package/booker-memento):

```
npm install --save booker-memento
```

##Example

```javascript
var Memento = require("booker-memento");

var memento = new Memento("secret");

var user = {
  email: "user@gmail.com",
  hash: "C6XbuRC.{5}WztufMP<u*^>c8_k~"
};

var passwordResetToken = memento.createToken(user);

passwordResetToken; // 1436012310:8c54cee7bef71a272a6116c5b11fa06362e5d7a7

var valid = memento.verifyToken(user);

valid; // true

user.salt = "123";

var valid = memento.verifyToken(user, passwordResetToken);

valid; // false
```
