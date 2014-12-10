/* jshint expr:true */
var chai   = require('chai'),
    expect = chai.expect;

var mongoose = require('mongoose'),
    cryptify = require( '../' + require('../package.json').main ),
    bcp      = require('bcrypt');

describe('Cryptify', function () {
  var _model, testModel;

  before(function ( done ) {
    mongoose.connect('localhost/cryptify-test');

    _model = new mongoose.Schema({
      secured: {
        data: String
      },
      securedPath: String
    });

    var _schema = _model.plugin(cryptify, {
      paths: [ 'secured.data', 'securedPath' ],
      factor: 10
    });

    testModel = mongoose.model('CryptifyTest', _schema);

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

  it('should handle undefined paths', function ( done ) {
    var testRecord = new testModel({
      secured: {
        data: 'test'
      }
    });

    testRecord.save(function ( err, doc ) {
      if( err ) {
        throw err;
      }

      expect(doc, 'document').to.exist; // jshint ignore:line

      expect(doc.securedPath).not.to.exist;

      doc.securedPath = 'test2';

      doc.save(function ( err, updated ) {
        expect(err).to.not.exist;
        expect(bcp.compareSync('test2', updated.securedPath)).to.equal(true);

        done();
      });
    });
  });
});
