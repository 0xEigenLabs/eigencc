var EC = require('elliptic').ec;
var ec = new EC('secp256k1');
var asn1 = require('asn1.js');

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
console.log(x, x2)
