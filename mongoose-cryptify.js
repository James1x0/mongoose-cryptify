/*
  Mongoose Cryptify
*/

var bcp      = require('bcrypt'),
    Promise  = require('bluebird'); // jshint ignore:line

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

    var parseDocument = function ( err, previous ) {
      if( err ) {
        next( err );
      }

      Promise.reduce(paths, function ( doc, path ) {
        var raw           = _getPathValue( doc, path ),
            previousValue = ( previous ) ? _getPathValue( previous, path ) : false;

        if( !raw || ( !!previousValue && previousValue === raw ) ) {
          return doc;
        }

        return _generateHash( raw , workFactor ).then(function ( hash ) {
          _setPathValue( doc, path, hash );
          return doc;
        });
      }, doc).then(function ( newDoc ) {
        next.call( newDoc );
      }).catch( next );
    };

    if( doc.isNew ) {
      parseDocument();
    } else {
      doc.constructor.findById(doc._id, parseDocument);
    }
  });

  if ( options.disableComparator !== false ) {
    schema.methods.compareHash = function ( rhs, path ) {
      var modelPath = path || 'password';

      return new Promise((resolve, reject) => {
        bcp.compare(rhs, this[modelPath], function (err, res) {
          if ( err ) {
            return reject(err);
          }

          resolve(res);
        })
      });
    };
  }

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

/**
 * Get Path Value
 * @param  {Object} recursive Object to traverse
 * @param  {Array} pathArray  Array of paths
 * @return {Mixed}            Value
 */
function _getPathValue ( recursive, pathArray ) {
  pathArray.forEach(function ( subpath ) {
    recursive = recursive[ subpath ];
  });

  return recursive;
}

function _setPathValue ( recursive, pathArray, value ) {
  var len = pathArray.length - 1;

  for ( var i = 0; i < len; i++ ) {
    recursive = recursive[ pathArray[ i ] ];
  }

  recursive[ pathArray[ len ] ] = value;
}
