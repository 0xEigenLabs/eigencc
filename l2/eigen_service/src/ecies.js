// Implemention of ECIES specified in https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme
'use strict';

const crypto = require('crypto');
const assert = require('assert');
var EC = require("elliptic").ec;
var ec = new EC("p256");
const empty_buffer = Buffer.allocUnsafe ? Buffer.allocUnsafe(0) : Buffer.from([]);
const AUTH_TAG_LEN = 16;
const IV_LEN = 12;

// E
function symmetricEncrypt(cypherName, iv, key, plaintext) {
    let cipher = crypto.createCipheriv(cypherName, key, iv);
    var encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    let tag  = cipher.getAuthTag()
    return Buffer.concat([iv, tag, encrypted]);
}

// E-1
function symmetricDecrypt(cypherName, key, cipherText) {
    // convert data to buffers
    let iv = cipherText.slice(0, IV_LEN);
    let tag = cipherText.slice(IV_LEN, IV_LEN + AUTH_TAG_LEN);
    let text = cipherText.slice(IV_LEN + AUTH_TAG_LEN);
    let decipher = crypto.createDecipheriv(cypherName, key, iv);
    decipher.setAuthTag(tag);
    let dec = decipher.update(text) + decipher.final();
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

    const ephemPrivateKey = ec.genKeyPair();
    // R
    const ephemPublicKey = Buffer.from(ephemPrivateKey.getPublic("arr"));
    // S
    const sharedSecret = Buffer.from(ephemPrivateKey.derive(publicKey).toArray());

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
    return Buffer.concat([ephemPublicKey, bufCipherText, tag]);
};

exports.decrypt = function (keyPair, message, options) {
    options = makeUpOptions(options);

    const publicKeyLength = keyPair.getPublic("arr").length;
    // R
    const R = message.slice(0, publicKeyLength);
    let keyPair2 = ec.keyFromPublic(R);
    let publicKey = keyPair2.getPublic();
    // c
    const cipherText = message.slice(publicKeyLength, message.length - options.macLength);
    // d
    const messageTag = message.slice(message.length - options.macLength);

    // S
    const sharedSecret = Buffer.from(keyPair.derive(publicKey).toArray());

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
