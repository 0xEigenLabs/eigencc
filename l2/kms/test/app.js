var EC = require('elliptic').ec;
var ec = new EC('secp256k1');
var asn1 = require('asn1.js');

var key = ec.genKeyPair();
var publicKey = key.getPublic(false);



