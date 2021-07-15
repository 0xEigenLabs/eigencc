var EC = require('elliptic').ec;
var ec = new EC('secp256k1');
var ecies = require("../src/ecies.js");
const crypto = require("crypto");
var assert = require('assert');

var key = ec.genKeyPair();
var publicKey = key.getPublic(false);

var pubPoint = key.getPublic();
var x = pubPoint.getX();
var y = pubPoint.getY();

//console.log(pubPoint)

var pub = pubPoint.encode('hex')
//console.log(pub)

var key = ec.keyFromPublic(pub, 'hex');
var publicKey2 = key.getPublic()
var x2 = publicKey2.getX();
var y2 = publicKey2.getY();
console.log(x,x2);

let msg = "Hello, Eigen";
const KEY = Buffer.from(crypto.randomBytes(32), 'utf8');
const iv2 = Buffer.from(crypto.randomBytes(12), 'utf8');
console.log('iv2', iv2);

let encrypted2 = ecies.aes_enc('aes-256-gcm', iv2, KEY, msg)
let decrypted2 = ecies.aes_dec('aes-256-gcm', KEY, encrypted2)
assert(decrypted2 == msg);
console.log("aes worker well", decrypted2, iv2);

// default option
const options = {
  hashName: 'sha512',
  hashLength: 64,
  macName: 'sha256',
  macLength: 32,
  curveName: 'secp256k1',
  symmetricCypherName: 'aes-256-gcm',
  keyFormat: 'uncompressed',
  s1: null, // optional shared information1
  s2: null // optional shared information2
}
const ecdh = crypto.createECDH(options.curveName);
ecdh.generateKeys();

console.log(ecdh.getPublicKey().toString('hex'));
const encryptedText = ecies.encrypt(ecdh.getPublicKey(), msg, options);
console.log("cipher", encryptedText.toString('hex'));
const decryptedText = ecies.decrypt(ecdh, encryptedText, options);
console.log(msg, decryptedText)
assert(msg == decryptedText);
