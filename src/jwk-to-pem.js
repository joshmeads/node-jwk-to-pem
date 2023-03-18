'use strict';

const ec = require('./ec');
const rsa = require('./rsa');
const ed25519 = require('./ed25519');

/**
 *
 * @param {{kty:'EC', crv:string, d:string, x?:string, y?:string} | {kty:'EC', crv:string, x:string, y:string} | {kty:'RSA', e:string, n:string, d?:string, p?:string, q?:string, dp?:string, dq?:string, qi?:string}} jwk
 * @param {{private:boolean}=} opts
 * @returns {string}
 */
function jwkToBuffer(jwk, opts) {
	let _jwk = jwk;
	if (typeof jwk === 'string') {
		try {
			const parsed = JSON.parse(Buffer.from(jwk, 'base64').toString('ascii'));
			_jwk = parsed;
		} catch {}
	}

	if (typeof jwk !== 'object' || null === jwk) {
		throw new TypeError('Expected "jwk" to be an Object');
	}

	var kty = jwk.kty;
	if ('string' !== typeof kty) {
		throw new TypeError('Expected "jwk.kty" to be a String');
	}

	opts = opts || {};
	opts.private = opts.private === true;

	switch (kty) {
		case 'EC': {
			return ec(jwk, opts);
		}
		case 'RSA': {
			return rsa(jwk, opts);
		}
		case 'OKP': {
			return ed25519(jwk, opts);
		}
		default: {
			throw new Error('Unsupported key type "' + kty + '"');
		}
	}
}

module.exports = jwkToBuffer;
