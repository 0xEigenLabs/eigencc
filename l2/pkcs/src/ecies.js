// Implemention of ECIES specified in https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme
'use strict';

const crypto = require('crypto');
const assert = require('assert');
const empty_buffer = Buffer.allocUnsafe ? Buffer.allocUnsafe(0) : Buffer.from([]);
const SALT_LEN = 32;
const AUTH_TAG_LEN = 16;
const IV_LEN = 12;

// E
function symmetricEncrypt(cypherName, iv, key, plaintext) {
    let cipher = crypto.createCipheriv(cypherName, key, iv);
    var encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);

    let tag  = cipher.getAuthTag()
    var salt = crypto.randomBytes(SALT_LEN);
    return Buffer.concat([salt, iv, tag, encrypted]).toString('base64');
}

// E-1
function symmetricDecrypt(cypherName, key, ciphertext) {
    var bData = Buffer.from(ciphertext, 'base64');
    // convert data to buffers
    let salt = bData.slice(0, SALT_LEN);
    let iv = bData.slice(SALT_LEN, SALT_LEN + IV_LEN);
    let tag = bData.slice(SALT_LEN + IV_LEN, SALT_LEN + IV_LEN + AUTH_TAG_LEN);
    let text = bData.slice(SALT_LEN + IV_LEN + AUTH_TAG_LEN);
    let cipher = crypto.createDecipheriv(cypherName, key, iv);
    cipher.setAuthTag(tag);
    let dec = cipher.update(text, 'binary', 'utf8') + cipher.final('utf8');
    return dec;
}
exports.aes_enc = symmetricEncrypt
exports.aes_dec = symmetricDecrypt

// KDF
function hashMessage(cypherName, message) {
    return crypto.createHash(cypherName).update(message).digest();
}

// MAC
function macMessage(cypherName, key, message) {
    return crypto.createHmac(cypherName, key).update(message).digest();
}

// Compare two buffers in constant time to prevent timing attacks.
function equalConstTime(b1, b2) {
    if (b1.length !== b2.length) {
        return false;
    }
    let result = 0;
    for (let i = 0; i < b1.length; i++) {
        result |= b1[i] ^ b2[i];  // jshint ignore:line
    }
    return result === 0;
}

function makeUpOptions(options) {
    options = options || {};
    if (options.hashName == undefined) {
        options.hashName = 'sha256';
    }
    if (options.hashLength == undefined) {
        options.hashLength = hashMessage(options.hashName, '').length;
    }
    if (options.macName == undefined) {
        options.macName = 'sha256';
    }
    if (options.macLength == undefined) {
        options.macLength = macMessage(options.hashName, '', '').length;
    }
    if (options.curveName == undefined) {
        options.curveName = 'secp256k1';
    }
    if (options.keyFormat == undefined) {
        options.keyFormat = 'uncompressed';
    }

    // S1 (optional shared information1)
    if (options.s1 == undefined) {
        options.s1 = empty_buffer;
    }
    // S2 (optional shared information2)
    if (options.s2 == undefined) {
        options.s2 = empty_buffer;
    }
    return options;
}

exports.encrypt = function (publicKey, message, options) {
    options = makeUpOptions(options);

    const ecdh = crypto.createECDH(options.curveName);
    // R
    const R = ecdh.generateKeys(null, options.keyFormat);
    // S
    const sharedSecret = ecdh.computeSecret(publicKey);

    // uses KDF to derive a symmetric encryption and a MAC keys:
    // Ke || Km = KDF(S || S1)
    const hash = hashMessage(
        options.hashName,
        Buffer.concat(
            [sharedSecret, options.s1],
            sharedSecret.length + options.s1.length
        )
    );
    // Ke
    const encryptionKey = hash.slice(0, hash.length/2);
    // Km
    const macKey = hash.slice(hash.length/2);

    // encrypts the message:
    // c = E(Ke; m);
    const iv = Buffer.from(crypto.randomBytes(IV_LEN), 'utf8');
    const cipherText = symmetricEncrypt(options.symmetricCypherName, iv, encryptionKey, message);
    let bufCipherText = Buffer.from(cipherText, 'base64')
    // computes the tag of encrypted message and S2:
    // d = MAC(Km; c || S2)
    const tag = macMessage(
        options.macName,
        macKey,
        Buffer.concat(
            [bufCipherText, options.s2],
            bufCipherText.length + options.s2.length
        ),
    );
    // outputs R || c || d
    return Buffer.concat([R, bufCipherText, tag]);
};

exports.decrypt = function (ecdh, message, options) {
    options = makeUpOptions(options);

    const publicKeyLength = ecdh.getPublicKey(null, options.keyFormat).length;
    // R
    const R = message.slice(0, publicKeyLength);
    // c
    const cipherText = message.slice(publicKeyLength, message.length - options.macLength);
    // d
    const messageTag = message.slice(message.length - options.macLength);

    // S
    const sharedSecret = ecdh.computeSecret(R);

    // derives keys the same way as Alice did:
    // Ke || Km = KDF(S || S1)
    const hash = hashMessage(
        options.hashName,
        Buffer.concat(
            [sharedSecret, options.s1],
            sharedSecret.length + options.s1.length
        )
    );
    // Ke
    const encryptionKey = hash.slice(0, hash.length/2);
    // Km
    const macKey = hash.slice(hash.length/2);

    // uses MAC to check the tag
    const keyTag = macMessage(
        options.macName,
        macKey,
        Buffer.concat(
            [cipherText, options.s2],
            cipherText.length + options.s2.length
        )
    );

    // outputs failed if d != MAC(Km; c || S2);
    assert(equalConstTime(messageTag, keyTag), "Bad MAC");

    // uses symmetric encryption scheme to decrypt the message
    // m = E-1(Ke; c)
    return symmetricDecrypt(options.symmetricCypherName, encryptionKey, cipherText);
}
