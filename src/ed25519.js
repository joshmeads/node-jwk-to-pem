'use strict';

var asn1 = require('asn1.js'),
	Buffer = require('safe-buffer').Buffer,
	EDDSA = require('elliptic').eddsa;

var b64ToBn = require('./b64-to-bn');

var PublicKeyInfo = require('./asn1/public-key-info'),
	PrivateKeyInfo = require('./asn1/private-key-info'),
	Version = require('./asn1/version');

var OKPParameters = asn1.define('OKPParameters', /* @this */ function() {
	this.choice({
		namedCurve: this.objid()
	});
});

var okpPrivkeyVer1 = 1;

var OKPPrivateKey = asn1.define('OKPPrivateKey', /* @this */ function() {
	this.seq().obj(
		this.key('version').use(Version),
		this.key('privateKey').octstr(),
		this.key('parameters').explicit(0).optional().any(),
		this.key('publicKey').explicit(1).optional().bitstr()
	);
});

var curves = {
	'Ed25519': 'ed25519',
};

var oids = {
	'ed25519': [1, 3, 101, 112],
};
var parameters = {};
var algorithms = {};
Object.keys(oids).forEach(function(crv) {
	parameters[crv] = OKPParameters.encode({
		type: 'namedCurve',
		value: oids[crv]
	}, 'der');
	algorithms[crv] = {
		algorithm:  [1, 2, 840, 10045, 2, 1],
		parameters: parameters[crv]
	};
});
oids = null;

function okpJwkToBuffer(jwk, opts) {
	if ('string' !== typeof jwk.crv) {
		throw new TypeError('Expected "jwk.crv" to be a String');
	}

	var hasD = 'string' === typeof jwk.d;
	var xyTypes = hasD
		? ['undefined', 'string']
		: ['string'];

	if (-1 === xyTypes.indexOf(typeof jwk.x)) {
		throw new TypeError('Expected "jwk.x" to be a String');
	}

	if (-1 === xyTypes.indexOf(typeof jwk.y)) {
		throw new TypeError('Expected "jwk.y" to be a String');
	}

	if (opts.private && !hasD) {
		throw new TypeError('Expected "jwk.d" to be a String');
	}

	var curveName = curves[jwk.crv];
	if (!curveName) {
		throw new Error('Unsupported curve "' + jwk.crv + '"');
	}

	var curve = new EDDSA(curveName);

	var key = {};

	var hasPub = jwk.x && jwk.y;
	if (hasPub) {
		key.pub = {
			x: b64ToBn(jwk.x, false),
			y: b64ToBn(jwk.y, false)
		};
	}

	if (opts.private || !hasPub) {
		key.priv = b64ToBn(jwk.d, true);
	}

	key = curve.keyPair(key);

	var keyValidation = key.validate();
	if (!keyValidation.result) {
		throw new Error('Invalid key for curve: "' + keyValidation.reason + '"');
	}

	var result = keyToPem(jwk.crv, key, opts);

	return result;
}

function keyToPem(crv, key, opts) {
	var compact = false;
	var publicKey = key.getPublic(compact, 'hex');
	publicKey = Buffer.from(publicKey, 'hex');
	publicKey = {
		unused: 0,
		data: publicKey
	};

	var result;
	if (opts.private) {
		var privateKey = key.getPrivate('hex');
		privateKey = Buffer.from(privateKey, 'hex');

		result = PrivateKeyInfo.encode({
			version: 0,
			privateKeyAlgorithm: algorithms[crv],
			privateKey: OKPPrivateKey.encode({
				version: okpPrivkeyVer1,
				privateKey: privateKey,
				parameters: parameters[crv],
				publicKey: publicKey
			}, 'der')
		}, 'pem', {
			label: 'PRIVATE KEY'
		});

		privateKey.fill(0);
	} else {
		result = PublicKeyInfo.encode({
			algorithm: algorithms[crv],
			PublicKey: publicKey
		}, 'pem', {
			label: 'PUBLIC KEY'
		});
	}

	// This is in an if incase asn1.js adds a trailing \n
	// istanbul ignore else
	if ('\n' !== result.slice(-1)) {
		result += '\n';
	}

	return result;
}

module.exports = okpJwkToBuffer;
