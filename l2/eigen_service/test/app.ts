declare const Buffer;
import {ec as EC} from "elliptic"
//const EC = elliptic.ec;
const ec = new EC("p256");

import * as ecies from "../src/ecies";
import * as crypto from "crypto";

let msg = "Hello, Eigen, Privacy Computing!";
const KEY = Buffer.from(crypto.randomBytes(32), 'utf8');
const iv2 = Buffer.from(crypto.randomBytes(12), 'utf8');

let encrypted2 = ecies.aes_enc('aes-256-gcm', iv2, KEY, msg)
let decrypted2 = ecies.aes_dec('aes-256-gcm', KEY, encrypted2)
if (decrypted2 != msg) {
    throw new Error("decrypt failed")
}
//console.log("aes worker well", decrypted2, iv2);

function test_ecies() {
    // default option
    const options = {
        hashName: 'sha512',
        hashLength: 64,
        macName: 'sha256',
        macLength: 32,
        curveName: 'prime256v1',
        symmetricCypherName: 'aes-256-gcm',
        keyFormat: 'uncompressed',
        s1: null, // optional shared information1
        s2: null // optional shared information2
    }
    let keyPair = ec.genKeyPair();
    let publicKey = keyPair.getPublic();
    const encryptedText = ecies.encrypt(publicKey, msg, options);
    const decryptedText = ecies.decrypt(keyPair, encryptedText, options);
    if (msg != decryptedText) {
        throw new Error("decrypted2 failed")
    }
}

function test_ecies_with_rs() {
    // default option
    const options = {
        hashName: 'sha512',
        hashLength: 64,
        macName: 'sha256',
        macLength: 32,
        curveName: 'prime256v1',
        symmetricCypherName: 'aes-256-gcm',
        keyFormat: 'uncompressed',
        s1: null, // optional shared information1
        s2: null // optional shared information2
    }
    let pub = "04a52438a5c1bba393d167994974b6d299bbdb078263144c9d9429bb65bb151fa3718657caea7bb5adef04a8cf8d40ff20bbc3a9330f04c2acb5b209cd25a2d863";
    let keyPair = ec.keyFromPublic(pub, "hex");
    let publicKey = keyPair.getPublic();
    console.log("public: ", keyPair.getPublic('hex'));
    const encryptedText = ecies.encrypt(publicKey, msg, options);
    console.log("cipher", encryptedText.toString('hex'));

    let priv = "404a7d7eb5f367ba756dfd1c4f3b14fad4b1000a7cbac2497edac02eb078aab9"
    let keyPair2 = ec.keyFromPrivate(priv, "hex");
    console.log(keyPair2.getPublic("hex"));
    const decryptedText = ecies.decrypt(keyPair2, encryptedText, options);
    console.log(msg, decryptedText)
    //assert(msg == decryptedText);
}

test_ecies_with_rs();
