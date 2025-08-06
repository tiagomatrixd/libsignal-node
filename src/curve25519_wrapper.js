const crypto = require('../build/Release/signal_crypto');
const nodeCrypto = require('crypto');
const basepoint = new Uint8Array(32);
basepoint[0] = 9;

exports.keyPair = function(privKey) {
    const priv = new Uint8Array(privKey);
    priv[0]  &= 248;
    priv[31] &= 127;
    priv[31] |= 64;

    const pubKey = crypto.curve25519_donna(priv, basepoint);

    return {
        pubKey: Buffer.from(pubKey),
        privKey: Buffer.from(priv)
    };
};

// Compatibilidade: generateKeyPair sem parâmetros gera chave aleatória
exports.generateKeyPair = function(privKey) {
    if (!privKey) {
        privKey = nodeCrypto.randomBytes(32);
    }
    return exports.keyPair(privKey);
};

exports.sharedSecret = function(pubKey, privKey) {
    const priv = new Uint8Array(privKey);
    priv[0]  &= 248;
    priv[31] &= 127;
    priv[31] |= 64;

    return Buffer.from(crypto.curve25519_donna(priv, new Uint8Array(pubKey)));
};

// Alias para compatibilidade com curve.js  
exports.sharedKey = exports.sharedSecret;

exports.sign = function(privKey, message) {
    return Buffer.from(crypto.curve25519_sign(new Uint8Array(privKey), new Uint8Array(message)));
};

exports.verify = function(pubKey, message, sig) {
    return crypto.curve25519_verify(new Uint8Array(sig), new Uint8Array(pubKey), new Uint8Array(message));
};
