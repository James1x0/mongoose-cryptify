/* jshint expr:true */
var chai   = require('chai'),
    expect = chai.expect;

var mongoose = require('mongoose'),
    bcp      = require('bcrypt');

mongoose.Promise = require('bluebird');

var createModel = function ( name, schema ) {
  try {
    return mongoose.model( name );
  } catch ( err ) {
    return mongoose.model( name, schema );
  }
};

describe('Cryptify', function () {
  var _model, testModel,
      cryptify = require( '../' + require('../package.json').main );

  before(function ( done ) {
    mongoose.connect('localhost/cryptify-test');

    _model = new mongoose.Schema({
      secured: {
        data: String
      },
      securedPath: String,
      password: String
    });

    var _schema = _model.plugin(cryptify, {
      paths: [ 'secured.data', 'securedPath', 'password' ],
      factor: 10
    });

    testModel = createModel('CryptifyTest', _schema);

    done();
  });

  after(function ( done ) {
    mongoose.connection.db.dropDatabase(function () {
      mongoose.disconnect(function () {
        done();
      });
    });
  });

  it('should encrypt paths', function ( done ) {
    var testRecord = new testModel({
      secured: {
        data: 'test'
      },
      securedPath: 'test2'
    });

    testRecord.save(function ( err, doc ) {
      if( err ) throw err;

      expect(doc, 'document').to.exist; // jshint ignore:line

      expect(bcp.compareSync('test', doc.secured.data)).to.equal(true);
      expect(bcp.compareSync('test2', doc.secured.data)).to.equal(false);

      expect(bcp.compareSync('test2', doc.securedPath)).to.equal(true);
      expect(bcp.compareSync('test3', doc.securedPath)).to.equal(false);

      doc.securedPath = 'test3';

      doc.save(function ( err, doc ) {
        if( err ) throw err;

        expect(bcp.compareSync('test3', doc.securedPath)).to.equal(true);
        expect(bcp.compareSync('test2', doc.securedPath)).to.equal(false);

        done();
      });
    });
  });

  it('should handle undefined paths', function ( done ) {
    var testRecord = new testModel({
      secured: {
        data: 'test'
      }
    });

    testRecord.save(function ( err, doc ) {
      if( err ) throw err;

      expect(doc, 'document').to.exist;

      expect(doc.securedPath).not.to.exist;

      doc.securedPath = 'test2';

      doc.save(function ( err, updated ) {
        if( err ) throw err;

        expect(bcp.compareSync('test2', updated.securedPath)).to.equal(true);

        done();
      });
    });
  });

  it('should handle updates', function ( done ) {
    var testRecord = new testModel({
      secured: {
        data: 'test'
      }
    });

    testRecord.save(function ( err, doc ) {
      if( err ) throw err;

      doc.securedPath = 'test';

      doc.save(function ( err, updated ) {
        if( err ) throw err;

        expect(bcp.compareSync('test', updated.secured.data)).to.equal(true);

        done();
      });
    });
  });

  describe('Cryptify#comparePassword', () => {
    it('should test true', done => {
      var testRecord = new testModel({
        password: 'test'
      });

      testRecord.save().then(doc => {
        return doc.compareHash('test');
      })
      .then(result => {
        expect(result).to.be.true;
        done();
      })
      .catch(done);
    });

    it('should test false', done => {
      var testRecord = new testModel({
        password: 'test'
      });

      testRecord.save().then(doc => {
        return doc.compareHash('nottest');
      })
      .then(result => {
        expect(result).to.be.false;
        done();
      })
      .catch(done);
    });
  });
});
