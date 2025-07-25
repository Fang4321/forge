/**
 * JavaScript implementation of ECDSA.
 *
 * Copyright (c) 2021 HAMANO Tsukasa <hamano@osstech.co.jp>
 *
 * This implementation is based on the noble-curves
 *
 * https://github.com/paulmillr/noble-curves
 */
var forge = require('./forge');
require('./asn1');
require('./jsbn');
require('./random');
require('./sha512');
var util = require('./util');
// Import specific curves from noble-curves
var { secp256k1 } = require('@noble/curves/secp256k1');
var { p256, p384, p521 } = require('@noble/curves/nist');
var { bytesToHex, hexToBytes } = require('@noble/curves/abstract/utils');
var asn1Validator = require('./asn1-validator');
var publicKeyInfoValidator = asn1Validator.publicKeyInfoValidator;
var privateKeyValidator = asn1Validator.privateKeyValidator;
var asn1 = forge.asn1;

if(typeof BigInteger === 'undefined') {
  var BigInteger = forge.jsbn.BigInteger;
}

var ByteBuffer = util.ByteBuffer;
var NativeBuffer = typeof Buffer === 'undefined' ? Uint8Array : Buffer;

forge.pki = forge.pki || {};
module.exports = forge.pki.ecdsa = forge.ecdsa = forge.ecdsa || {};
var ecdsa = forge.ecdsa;

ecdsa.constants = {};

/*
 * Supported namedCurve listed here:
 * https://github.com/paulmillr/noble-curves
 * Note: p192 and p224 are not supported by noble-curves due to security concerns
 */
ecdsa.supportedCueves = [
  'p256',     // secp256r1, prime256v1
  'p384',     // secp384r1
  'p521',     // secp521r1
  'secp256k1',// secp256k1
];

// Noble-curves compatibility layer
var nobleCurvesMap = {
  'p256': p256,
  'p384': p384,
  'p521': p521,
  'secp256k1': secp256k1
};

// Note: Using noble-curves utility functions for byte conversion

// Create elliptic-compatible wrapper for noble-curves
function createEllipticWrapper(curveName) {
  var nobleCurve = nobleCurvesMap[curveName];
  if (!nobleCurve) {
    throw new Error('Unsupported curve: ' + curveName);
  }

  return {
    curveName: curveName,
    genKeyPair: function(options) {
      options = options || {};
      var privateKey = nobleCurve.utils.randomPrivateKey();
      var publicKey = nobleCurve.getPublicKey(privateKey);

      return {
        getPrivate: function() { return privateKey; },
        getPublic: function() {
          return {
            encode: function(format) {
              if (format === 'hex') {
                return bytesToHex(publicKey);
              }
              return publicKey;
            }
          };
        },
        ec: this
      };
    },
    keyFromPrivate: function(privateKey) {
      if (typeof privateKey === 'string') {
        privateKey = hexToBytes(privateKey);
      }
      var publicKey = nobleCurve.getPublicKey(privateKey);
      return {
        getPrivate: function() {
          return {
            toString: function(format) {
              if (format === 'hex') {
                return bytesToHex(privateKey);
              }
              return privateKey;
            },
            toArray: function() {
              return Array.from(privateKey);
            }
          };
        },
        getPublic: function() {
          return {
            encode: function(format) {
              if (format === 'hex') {
                return bytesToHex(publicKey);
              }
              return publicKey;
            }
          };
        },
        ec: this
      };
    },
    keyFromPublic: function(publicKey) {
      if (typeof publicKey === 'string') {
        publicKey = hexToBytes(publicKey);
      }
      return {
        getPublic: function() {
          return {
            encode: function(format) {
              if (format === 'hex') {
                return bytesToHex(publicKey);
              }
              return publicKey;
            }
          };
        },
        ec: this
      };
    },
    sign: function(msgHash, privateKey) {
      if (typeof msgHash === 'string') {
        msgHash = hexToBytes(msgHash);
      }
      if (typeof privateKey === 'string') {
        privateKey = hexToBytes(privateKey);
      }
      var signature = nobleCurve.sign(msgHash, privateKey);
      return {
        toDER: function() {
          return signature.toDERRawBytes();
        }
      };
    },
    verify: function(msgHash, signature, publicKey, encoding) {
      if (typeof msgHash === 'string') {
        msgHash = hexToBytes(msgHash);
      }
      if (typeof signature === 'string') {
        signature = hexToBytes(signature);
      }
      if (typeof publicKey === 'string') {
        publicKey = hexToBytes(publicKey);
      }
      return nobleCurve.verify(signature, msgHash, publicKey);
    }
  };
}

/*
 * RCF5915: Elliptic Curve Private Key Format
 * https://datatracker.ietf.org/doc/html/rfc5915
 *
 * ECPrivateKey ::= SEQUENCE {
 *   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *   privateKey     OCTET STRING,
 *   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 *   publicKey  [1] BIT STRING OPTIONAL
 * }
 */
var ecPrivateKeyValidator = {
  name: 'ECPrivateKey',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    name: 'ECPrivateKey.version',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    capture: 'version',
  }, {
    name: 'ECPrivateKey.privateKey',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.OCTETSTRING,
    capture: 'privateKey',
  }, {
    tagClass: asn1.Class.CONTEXT_SPECIFIC,
    type: 0x0,
    optional: true,
    value: [{
      name: 'ECPrivateKey.parameters',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      captureAsn1: 'parameters',
    }],
  }, {
    tagClass: asn1.Class.CONTEXT_SPECIFIC,
    type: 0x1,
    optional: true,
    value: [{
      name: 'ECPrivateKey.publicKey',
      type: asn1.Type.BITSTRING,
      captureAsn1: 'publicKey',
    }],
  }]
};

var ecSpecifiedCurveValidator = {
  name: 'SpecifiedCurve',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    name: 'SpecifiedCurveVersion',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    capture: 'version',
  }, {
    name: 'SpecifiedCurve.FieldID',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'SpecifiedCurve.FieldID.fieldType',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      capture: 'fieldType',
    }, {
      name: 'SpecifiedCurve.FieldID.prime',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.INTEGER,
      capture: 'p',
    }]
  }, {
    name: 'SpecifiedCurve.Curve',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'SpecifiedCurve.Curve.a',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OCTETSTRING,
      capture: 'a',
    }, {
      name: 'SpecifiedCurve.Curve.b',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OCTETSTRING,
      capture: 'b',
    }]
  }, {
    name: 'SpecifiedCurve.Generator',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.OCTETSTRING,
    capture: 'g',
  }, {
    name: 'SpecifiedCurve.Order',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    capture: 'n',
  }, {
    name: 'SpecifiedCurve.Confactor',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    capture: 'c',
    optional: true
  }]
};

ecdsa.generateKeyPair = function(options) {
  options = options || {};
  var curveName = options.name || 'p256';
  var seed = options.seed;
  var errors = [];

  if (!(ecdsa.supportedCueves.includes(curveName))) {
    var error = new Error('unsupported curveName: ' + curveName);
    error.errors = errors;
    throw error;
  }

  var nobleCurve = nobleCurvesMap[curveName];
  if (!nobleCurve) {
    var error = new Error('unsupported curveName: ' + curveName);
    error.errors = errors;
    throw error;
  }

  var nobleCurve = nobleCurvesMap[curveName];
  var privateKey = nobleCurve.utils.randomPrivateKey();
  var publicKey = nobleCurve.getPublicKey(privateKey);

  var ec = createEllipticWrapper(curveName);
  return {
    publicKey: new ecdsa.ECPublicKey(ec, publicKey),
    privateKey: new ecdsa.ECPrivateKey(ec, privateKey)
  };
};

/**
 * Converts a ECPrivateKey to an ASN.1 representation.
 *
 * @param key the ECPrivateKey.
 *
 * @return the ASN.1 representation of an ECPrivateKey.
 */
ecdsa.privateKeyToAsn1 = function(key, options) {
  return key.toAsn1(options);
};

ecdsa.ECPublicKey = ECPublicKey = function(ec, publicKey) {
  this._ec = ec;
  this._publicKey = publicKey;
};

/**
 * Converts a public key from a RFC8410 ASN.1 encoding.
 *
 * @param obj - The asn1 representation of a public key.
 *
 * @return {ECPublicKey} - ECPublicKey object.
 */
ECPublicKey.fromAsn1 = function(obj) {
  var capture = {};
  var errors = [];
  if(!forge.asn1.validate(obj, publicKeyInfoValidator, capture, errors)) {
    var error = new Error('Cannot read PublicKeyInfo ASN.1 object.');
    error.errors = errors;
    throw error;
  }
  var publicKey = capture.subjectPublicKeyRaw;
  var params = capture.parameters;
  var curveName;
  if(params && params.type === forge.asn1.Type.OID) {
    var oid = forge.asn1.derToOid(params.value);
    curveName = forge.oids[oid];
    if(!ecdsa.supportedCueves.includes(curveName)) {
      var error = new Error('Unsupported curveName: ' + curveName);
      error.errors = errors;
      throw error;
    }
  } else if(params && params.type === forge.asn1.Type.SEQUENCE) {
    // For specified curves, we'll throw an error as noble-curves doesn't support custom curves
    var error = new Error('Specified curves not supported with noble-curves');
    error.errors = errors;
    throw error;
  } else {
    var error = new Error('no ECParameters');
    error.errors = errors;
    throw error;
  }

  var ec = createEllipticWrapper(curveName);
  return new ECPublicKey(ec, publicKey);
};

ECPublicKey.prototype.verify = function(msg, signature) {
    var nobleCurve = nobleCurvesMap[this._ec.curveName];
    if (!nobleCurve) {
      throw new Error('Unsupported curve: ' + this._ec.curveName);
    }

    // Convert message to bytes
    var msgBytes = msg;
    if (typeof msg === 'string') {
      msgBytes = hexToBytes(msg);
    }

    // Convert signature to bytes
    var sigBytes = signature;
    if (typeof signature === 'string') {
      // Convert string to byte array
      sigBytes = new Uint8Array(signature.length);
      for (var i = 0; i < signature.length; i++) {
        sigBytes[i] = signature.charCodeAt(i);
      }
    }

    // Use the public key bytes directly
    var pubKeyBytes = this._publicKey;

    return nobleCurve.verify(sigBytes, msgBytes, pubKeyBytes);
};

ECPublicKey.prototype.toString = function() {
  if (typeof this._publicKey === 'object' && this._publicKey.encode) {
    return this._publicKey.encode('hex');
  }
  return bytesToHex(this._publicKey);
};

ECPublicKey.prototype.getBytes = function() {
  var publicKeyBytes;
  if (typeof this._publicKey === 'object' && this._publicKey.encode) {
    publicKeyBytes = this._publicKey.encode();
  } else {
    publicKeyBytes = this._publicKey;
  }
  return String.fromCharCode.apply(null, publicKeyBytes);
};

ECPublicKey.prototype.toAsn1 = function(options) {
  var curveOID = forge.oids[this._ec.curveName];
  if (!curveOID) {
    var error = new Error('unsupported namedCurve or specifiedCurve.');
    throw error;
  }

  var obj = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
  var aid = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                asn1.oidToDer(forge.oids['ecPublicKey']).getBytes()),
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                asn1.oidToDer(curveOID).getBytes())]);
  obj.value.push(aid);
  obj.value.push(
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false,
                "\0" + this.getBytes()));
  return obj;
};

ECPublicKey.prototype.toDer = function() {
  return asn1.toDer(this.toAsn1()).getBytes();
};

ECPublicKey.prototype.toPem = function() {
  return '-----BEGIN PUBLIC KEY-----\n' +
    util.encode64(this.toDer(), 64) +
    '\n-----END PUBLIC KEY-----\n';
};


ecdsa.ECPrivateKey = ECPrivateKey = function(ec, privateKey) {
  this._ec = ec;
  this._privateKey = privateKey;
};

/**
 * Converts a private key from a RFC5915 ASN.1 Object.
 *
 * @param obj - The asn1 representation of a private key.
 *
 * @returns {Object} obj - The ASN.1 key object.
 * @returns {ECPrivateKey} ECPrivateKey object.
 */
ECPrivateKey.fromAsn1 = function(obj) {
  var capture = {};
  var errors = [];
  var valid = forge.asn1.validate(obj, ecPrivateKeyValidator, capture, errors);
  if(!valid) {
    var error = new Error('Invalid ECPrivateKey object.');
    error.errors = errors;
    throw error;
  }
  if (!capture.parameters) {
    var error = new Error('no ECPrivateKey.parameters.');
    error.errors = errors;
    throw error;
  }
  var oid = asn1.derToOid(capture.parameters.value)
  var curveName = forge.oids[oid];
  if (!ecdsa.supportedCueves.includes(curveName)) {
    var error = new Error('unsupported curveName: ' + curveName);
    error.errors = errors;
    throw error;
  }

  var ec = createEllipticWrapper(curveName);
  var privateKeyBytes = new Uint8Array(capture.privateKey.length);
  for (var i = 0; i < capture.privateKey.length; i++) {
    privateKeyBytes[i] = capture.privateKey.charCodeAt(i);
  }
  return new ECPrivateKey(ec, privateKeyBytes);
};

ECPrivateKey.prototype.sign = function(msg) {
  var nobleCurve = nobleCurvesMap[this._ec.curveName];
  if (!nobleCurve) {
    throw new Error('Unsupported curve: ' + this._ec.curveName);
  }

  // Convert message to bytes
  var msgBytes;
  if (typeof msg === 'string') {
    msgBytes = hexToBytes(msg);
  } else if (msg && typeof msg.digest === 'function') {
    // MessageDigest object from forge
    var digestBytes = msg.digest().getBytes();
    msgBytes = new Uint8Array(digestBytes.length);
    for (var i = 0; i < digestBytes.length; i++) {
      msgBytes[i] = digestBytes.charCodeAt(i);
    }
  } else if (msg instanceof Uint8Array) {
    msgBytes = msg;
  } else {
    throw new Error('Unsupported message format for ECDSA signing');
  }

  // Convert private key to bytes
  var privKeyBytes = this._privateKey;
  if (typeof this._privateKey === 'object' && this._privateKey.toArray) {
    privKeyBytes = new Uint8Array(this._privateKey.toArray());
  }

  var signature = nobleCurve.sign(msgBytes, privKeyBytes);
  return String.fromCharCode.apply(null, signature.toDERRawBytes());
};

ECPrivateKey.prototype.toString = function() {
  // Always return hex string representation
  return bytesToHex(this._privateKey);
};

ECPrivateKey.prototype.getBytes = function() {
  var privateKeyBytes;
  if (typeof this._privateKey === 'object' && this._privateKey.toArray) {
    privateKeyBytes = this._privateKey.toArray();
  } else {
    privateKeyBytes = Array.from(this._privateKey);
  }
  return String.fromCharCode.apply(null, privateKeyBytes);
};

ECPrivateKey.prototype.toAsn1 = function(options) {
  var curveOID = forge.oids[this._ec.curveName];
  if (!curveOID) {
    var error = new Error('unsupported namedCurve');
    throw error;
  }
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    asn1.create(asn1.Class.UNIVERSAL,
                asn1.Type.INTEGER, false,
                asn1.integerToDer(1).getBytes()),
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
                this.getBytes()),
    asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0x0, true, [
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                  asn1.oidToDer(curveOID).getBytes())
    ]),
  ]);
};

ECPrivateKey.prototype.toDer = function(options) {
  return asn1.toDer(this.toAsn1(options)).getBytes();
};

ECPrivateKey.prototype.toPem = function(options) {
  return '-----BEGIN EC PRIVATE KEY-----\n' +
    util.encode64(this.toDer(options), 64) +
    '\n-----END EC PRIVATE KEY-----\n';
};

/**
 * Converts an ECDSA public key to an ASN.1 SubjectPublicKeyInfo.
 *
 * @param key the ECDSA public key.
 *
 * @return the asn1 representation of a SubjectPublicKeyInfo.
 */
ecdsa.publicKeyToAsn1 = function(key) {
  if (!key._ec) {
    throw new Error('Key is not an ECDSA key');
  }

  var curveOID = forge.oids[key._ec.curveName];
  if (!curveOID) {
    throw new Error('Unsupported curve: ' + key._ec.curveName);
  }

  // SubjectPublicKeyInfo
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // AlgorithmIdentifier
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      // algorithm (ecPublicKey)
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
        asn1.oidToDer(forge.oids.ecPublicKey).getBytes()),
      // parameters (namedCurve)
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
        asn1.oidToDer(curveOID).getBytes())
    ]),
    // subjectPublicKey (BIT STRING)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false,
      "\0" + key.getBytes())
  ]);
};