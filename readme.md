## mongoose-cryptify
A mongoose.js plugin for encrypting schema paths via bcrypt.

### Installation
```
$ npm install mongoose-cryptify --save
```

### Usage
Mongoose plugin style.

```javascript
var mongoose = require('mongoose'),
    Schema   = mongoose.Schema,
    cryptify = require('mongoose-cryptify'),

var userSchema = new Schema({
  name: {
    first: String,
    last:  String
  },

  login: {
    email:    { type: String, unique: true },
    password: String
  }
});

// Attach some mongoose hooks
userSchema.plugin(cryptify, {
  paths: [ 'login.password' ], // Array of paths
  factor: 10                   // Bcrypt work factor
});

module.exports = mongoose.model('User', userSchema);
```

And then use bcrypt to compare the hash

```javascript

var bcrypt = require('bcrypt'),
    User   = require('path/to/model');

var document = new User({
  name: {
    first: 'Bob',
    last:  'Ross'
  },

  login: {
    email:    'bob@bobross.com',
    password: 'nicetree'
  }
});

document.save(function ( err, doc ) {
  if( err ) throw err;

  console.log(doc.login.password); // Some hashsum like $2a$10$lx8X2e2vIiapMwv4DqixJurDnqV8qn7W6Q7ocXygHGD9dp5kEspnm

  bcrypt.compare('nicetree', doc.login.password, function ( err, result ) {
    if( err ) throw err;

    console.log(result); // true
  })
});
```

See [bcrypt's repo](https://github.com/ncb000gt/node.bcrypt.js) for more details on work factor & comparing.


### Options

There are only two options used in mongoose-cryptify

+ **options.paths** {Array} (*Required*) Array of paths to encrypt
+ **options.factor** {Number} (*Optional*) Bcrypt work factor (rounds) (More info [here](https://github.com/ncb000gt/node.bcrypt.js#a-note-on-rounds))
