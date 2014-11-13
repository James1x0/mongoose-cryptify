/* jshint expr:true */
var chai   = require('chai'),
    expect = chai.expect;

var mongoose = require('mongoose');

var cryptify = require( '../' + require('../package.json').main ),
    bcp        = require('bcrypt');

describe('SchemaPlugin :: Cryptify', function () {
  var _model;

  beforeEach(function ( done ) {
    mongoose.connect('localhost/cryptify-test');
    _model = new mongoose.Schema({
      secured: {
        data: String
      },
      securedPath: String
    });

    done();
  });

  afterEach(function ( done ) {
    mongoose.connection.db.dropDatabase(function () {
      mongoose.disconnect(function () {
        done();
      });
    });
  });

  it('should encrypt fields', function ( done ) {
    var _schema = _model.plugin(cryptify, {
      paths: [ 'secured.data', 'securedPath' ],
      factor: 10
    });

    var testModel = mongoose.model('CryptifyTest', _schema);

    var testRecord = new testModel({
      secured: {
        data: 'test'
      },
      securedPath: 'test2'
    });

    testRecord.save(function ( err, doc ) {
      if( err ) {
        throw err;
      }

      expect(doc, 'document').to.exist; // jshint ignore:line

      expect(bcp.compareSync('test', doc.secured.data)).to.equal(true);
      expect(bcp.compareSync('test2', doc.secured.data)).to.equal(false);

      expect(bcp.compareSync('test2', doc.securedPath)).to.equal(true);
      expect(bcp.compareSync('test3', doc.securedPath)).to.equal(false);

      doc.securedPath = 'test3';

      doc.save(function ( err, doc ) {
        expect(err).to.not.exist;

        expect(bcp.compareSync('test3', doc.securedPath)).to.equal(true);
        expect(bcp.compareSync('test2', doc.securedPath)).to.equal(false);

        done();
      });
    });
  });
});
