var EC = require('elliptic').ec;
var ec = new EC('secp256k1');
var asn1 = require('asn1.js');
const ecies = require('ecies-geth');
const secp256k1 = require("secp256k1")

var key = ec.genKeyPair();
var publicKey = key.getPublic();
console.log("pubk length", publicKey)

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
console.log(x, x2)

// Encrypting the message for A.
ecies.encrypt(publicKey, Buffer.from('msg to a')).then(function(encrypted) {
  // A decrypting the message.
  ecies.decrypt(key.getPrivate(), encrypted).then(function(plaintext) {
    console.log('Message to part A', plaintext.toString());
  });
});
