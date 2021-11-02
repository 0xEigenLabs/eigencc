// Implemention of ECIES specified in https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme
'use strict';
declare const Buffer;

import * as crypto from 'crypto';
import * as elliptic from "elliptic"
const EC = elliptic.ec;
const ec = new EC("p256");
const empty_buffer = Buffer.allocUnsafe ? Buffer.allocUnsafe(0) : Buffer.from([]);
const AUTH_TAG_LEN = 16;
const IV_LEN = 12;

// E
function aes_enc(cypherName, iv, key, plaintext) {
    const cipher = crypto.createCipheriv(cypherName, key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag  = cipher.getAuthTag()
    return Buffer.concat([iv, tag, encrypted]);
}

// E-1
function aes_dec(cypherName, key, cipherText) {
    // convert data to buffers
    const iv = cipherText.slice(0, IV_LEN);
    const tag = cipherText.slice(IV_LEN, IV_LEN + AUTH_TAG_LEN);
    const text = cipherText.slice(IV_LEN + AUTH_TAG_LEN);
    const decipher = crypto.createDecipheriv(cypherName, key, iv);
    decipher.setAuthTag(tag);
    // const dec = decipher.update(text) + decipher.final();
    const dec = decipher.update(text) + decipher.final("utf8"); // TODO test
    return dec;
}

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

const encrypt = function (publicKey, message, options) {
    options = makeUpOptions(options);

    const ephemPrivateKey = ec.genKeyPair();
    // R
    // const ephemPublicKey = Buffer.from(ephemPrivateKey.getPublic("arr"));
    const ephemPublicKey = Buffer.from(ephemPrivateKey.getPublic("array"));
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
    const cipherText = aes_enc(options.symmetricCypherName, iv, encryptionKey, message);
    const bufCipherText = Buffer.from(cipherText, 'base64')
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

const decrypt = function (keyPair, message, options) {
    options = makeUpOptions(options);

    const publicKeyLength = keyPair.getPublic("arr").length;
    // R
    const R = message.slice(0, publicKeyLength);
    const keyPair2 = ec.keyFromPublic(R);
    const publicKey = keyPair2.getPublic();
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
    if (!equalConstTime(messageTag, keyTag)) throw new Error("Bad MAC");

    // uses symmetric encryption scheme to decrypt the message
    // m = E-1(Ke; c)
    return aes_dec(options.symmetricCypherName, encryptionKey, cipherText);
}

export {encrypt, decrypt, aes_dec, aes_enc};
