/*
  Mongoose Cryptify
*/

var bcp     = require('bcrypt'),
    Promise = require('bluebird'); // jshint ignore:line

module.exports = Cryptify;

/**
 * Cryptify Plugin Signature
 * 
 * @param  {Object} schema  Mongoose Schema
 * @param  {Object} options Options Hash
 * @return {Object}         Mongoose Schema
 */
function Cryptify ( schema, options ) {
  if( !options.paths ) {
    throw new Error('Cryptify requires "paths" to be specified in the options hash');
  }

  var paths = options.paths.map(function ( path ) {
    return path.split('.');
  });

  var workFactor = options.factor || 10;

  schema.pre('save', function ( next ) {
    var doc = this;

    var getPathValue = function ( pathArray ) {
      var recursive = doc;

      pathArray.forEach(function ( subpath ) {
        recursive = recursive[ subpath ];
      });

      return recursive;
    };

    var setPathValue = function ( recursive, pathArray, value ) {
      var len = pathArray.length - 1;

      for ( var i = 0; i < len; i++ ) {
        recursive = recursive[ pathArray[ i ] ];
      }

      recursive[ pathArray[ len ] ] = value;
    };

    Promise.reduce(paths, function ( doc, path ) {
      var raw = getPathValue( path );

      if( !raw ) {
        return doc;
      }

      return _generateHash( raw , workFactor ).then(function ( hash ) {
        setPathValue( doc, path, hash );
        return doc;
      });
    }, doc).then(function ( newDoc ) {
      next.call( newDoc );
    }).catch( next );
  });

  return schema;
}

/**
 * Generate Hash
 *
 * @private
 * 
 * @param  {String} raw
 * @return {Promise}
 */
function _generateHash ( raw, workFactor ) {
  return new Promise(function ( resolve, reject ) {
    bcp.genSalt(workFactor, function ( err, salt ) {
      if( err ) {
        return reject( err );
      }

      bcp.hash(raw, salt, function ( err, hash ) {
        if( err ) {
          return reject( err );
        }

        resolve( hash );
      });
    });
  });
}
