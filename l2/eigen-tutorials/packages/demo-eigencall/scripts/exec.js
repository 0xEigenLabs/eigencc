const { ethers } = require('hardhat')
const { expect } = require('chai')
const { eigenLog, requireEnvVariables } = require('arb-shared-dependencies')
const RLP = require('rlp')
const { Base64 } = require('js-base64');
const { Uint64BE } = require("int64-buffer");
const fetch = require('node-fetch');
const ecies = require('../../../../eigen_service/src/ecies')
const EC = require('elliptic').ec;
const ec = new EC('p256');

require('dotenv').config()

requireEnvVariables(['DEVNET_PRIVKEY', 'L2RPC', 'PKCS'])

function compose_decrypt(cipher) {
  return RLP.encode(["decrypt1", Base64.fromUint8Array(cipher), "", ""])
}

function compose_encrypt(num) {
  return RLP.encode(["encrypt1", num.toString(), "", ""])
}

function compose_add_cipher_cipher(cipher1, cipher2) {
  return RLP.encode(["add_cipher_cipher2", Base64.fromUint8Array(cipher1), Base64.fromUint8Array(cipher2), ""])
}

function compose_add_cipher_plain(cipher, plain) {
  return RLP.encode(["add_cipher_plain2", Base64.fromUint8Array(cipher), plain.toString(), ""])
}

function compose_sub_cipher_cipher(cipher1, cipher2) {
  return RLP.encode(["sub_cipher_cipher2", Base64.fromUint8Array(cipher1), Base64.fromUint8Array(cipher2), ""])
}

function compose_sub_cipher_plain(cipher, plain) {
  return RLP.encode(["sub_cipher_plain2", Base64.fromUint8Array(cipher), plain.toString(), ""])
}

const encrypt = async (contract, num) => {
  var encrypt_operator_encoding_string = compose_encrypt(num)
  var tx = await contract.call_eigenCall(encrypt_operator_encoding_string, {
    gasPrice: 0,
    gasLimit: 250000
  })

  var receipt = await tx.wait()
  var event = receipt.events.pop()

  rlp_encoded_return_value = event.args.returnValue;

  expect(rlp_encoded_return_value).not.equal(RLP.encode(""))

  var cipher_base64 = RLP.decode(rlp_encoded_return_value).toString()
  var cipher = Base64.toUint8Array(cipher_base64)
  return cipher
}

const decrypt = async (contract, cipher) => {
  var decrypt_operator_encoding_string = compose_decrypt(cipher)

  var tx = await contract.call_eigenCall(decrypt_operator_encoding_string, {
    gasPrice: 0,
    gasLimit: 250000
  })

  var receipt = await tx.wait()
  var event = receipt.events.pop()

  rlp_encoded_return_value = event.args.returnValue;

  expect(rlp_encoded_return_value).not.equal(RLP.encode(""))

  var plain = RLP.decode(rlp_encoded_return_value).toString()

  return parseInt(plain)
}

const add_cipher_cipher = async (contract, cipher1, cipher2) => {
  var add_cipher_cipher_operator_encoding_string = compose_add_cipher_cipher(cipher1, cipher2)
  var tx = await contract.call_eigenCall(add_cipher_cipher_operator_encoding_string, {
    gasPrice: 0,
    gasLimit: 250000
  })

  var receipt = await tx.wait()
  var event = receipt.events.pop()

  rlp_encoded_return_value = event.args.returnValue;

  expect(rlp_encoded_return_value).not.equal(RLP.encode(""))

  var cipher_base64 = RLP.decode(rlp_encoded_return_value).toString()
  var cipher = Base64.toUint8Array(cipher_base64)
  return cipher
}

const add_cipher_plain = async (contract, cipher, plain) => {
  var add_cipher_plain_operator_encoding_string = compose_add_cipher_plain(cipher, plain)
  var tx = await contract.call_eigenCall(add_cipher_plain_operator_encoding_string, {
    gasPrice: 0,
    gasLimit: 250000
  })

  var receipt = await tx.wait()
  var event = receipt.events.pop()

  rlp_encoded_return_value = event.args.returnValue;

  expect(rlp_encoded_return_value).not.equal(RLP.encode(""))

  var cipher_base64 = RLP.decode(rlp_encoded_return_value).toString()
  var cipher = Base64.toUint8Array(cipher_base64)
  return cipher
}

const sub_cipher_cipher = async (contract, cipher1, cipher2) => {
  var sub_cipher_cipher_operator_encoding_string = compose_sub_cipher_cipher(cipher1, cipher2)
  var tx = await contract.call_eigenCall(sub_cipher_cipher_operator_encoding_string, {
    gasPrice: 0,
    gasLimit: 250000
  })

  var receipt = await tx.wait()
  var event = receipt.events.pop()

  rlp_encoded_return_value = event.args.returnValue;

  expect(rlp_encoded_return_value).not.equal(RLP.encode(""))

  var cipher_base64 = RLP.decode(rlp_encoded_return_value).toString()
  var cipher = Base64.toUint8Array(cipher_base64)
  return cipher
}

const sub_cipher_plain = async (contract, cipher, plain) => {
  var sub_cipher_plain_operator_encoding_string = compose_sub_cipher_plain(cipher, plain)
  var tx = await contract.call_eigenCall(sub_cipher_plain_operator_encoding_string, {
    gasPrice: 0,
    gasLimit: 250000
  })

  var receipt = await tx.wait()
  var event = receipt.events.pop()

  rlp_encoded_return_value = event.args.returnValue;

  expect(rlp_encoded_return_value).not.equal(RLP.encode(""))

  var cipher_base64 = RLP.decode(rlp_encoded_return_value).toString()
  var cipher = Base64.toUint8Array(cipher_base64)
  return cipher
}

function ecies_encrypt(public_key, num) {
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

  const cipher = ecies.encrypt(public_key, (new Uint64BE(num)).toBuffer(), options);

  return cipher
}

const main = async () => {
  await eigenLog('Simple eigenCall demo')

  const res = await fetch(process.env['PKCS'] + '/store?digest=1', {
    method: 'GET',
    headers: { 'Content-Type': 'application/json' }
  })
    .then(response => response.json())

  expect(res.errno).to.equal(0)

  const public_key = res.data.public_key

  console.log("Public key get from pkcs: ", public_key)

  expect(public_key).not.equal("")

  let keyPair = ec.keyFromPublic(public_key, "hex");
  let publicKey = keyPair.getPublic();

  console.log("----------------------------------------------------")

  const l2Wallet = (await hre.ethers.getSigners())[0]
  console.log('Your wallet address:', l2Wallet.address)

  const L2EigencallDemo = await (
    await ethers.getContractFactory('EigencallDemo')
  ).connect(l2Wallet)
  console.log('Deploying EigencallDemo contract to L2')
  const l2eigencalldemo = await L2EigencallDemo.deploy({ gasLimit: 250000 })
  await l2eigencalldemo.deployed()
  console.log(`EigencallDemo contract is deployed to ${l2eigencalldemo.address}`)

  ////////////////////////////////////////////////////////////////////////////////////
  // 'encrypt' test
  var num = 123
  var cipher = ecies_encrypt(publicKey, num)

  // 'decrypt' test
  console.log("Going to 'decrypt' ", cipher)
  var decrypt_number = await decrypt(l2eigencalldemo, cipher)
  console.log("Success!")

  expect(decrypt_number).to.equal(num)
  console.log(`${num} -> encrypt -> decrypt is still ${num}`)
  ////////////////////////////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////////////////////////////
    // Self 'encrypt' and then 'decrypt' test
    var num = 123
  console.log("Going to 'encrypt' ", num)
  var cipher = await encrypt(l2eigencalldemo, num)
  console.log("Success!")

  // 'decrypt' test
  console.log("Going to 'decrypt' ", cipher)
  var decrypt_number = await decrypt(l2eigencalldemo, cipher)
  console.log("Success!")

  expect(decrypt_number).to.equal(num)
  console.log(`${num} -> encrypt -> decrypt is still ${num}`)
  ////////////////////////////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////////////////////////////
    // 'add_cipher_cipher' test
    var num1 = 100
  var num2 = 1

  console.log(`Going to 'add_cipher_cipher' ${num1}, ${num2}`)
  var cipher1 = ecies_encrypt(publicKey, num1)
  var cipher2 = ecies_encrypt(publicKey, num2)

  var result_cipher = await add_cipher_cipher(l2eigencalldemo, cipher1, cipher2)
  var result_number = await decrypt(l2eigencalldemo, result_cipher)

  expect(result_number).to.equal(num1 + num2)
  console.log(`add_cipher_cipher ${num1} ${num2} is ${num1 + num2}`)
  ////////////////////////////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////////////////////////////
    // 'add_cipher_plain' test
    var num1 = 100
  var num2 = 1

  console.log(`Going to 'add_cipher_plain' ${num1}, ${num2}`)
  var cipher1 = ecies_encrypt(publicKey, num1)

  var result_cipher = await add_cipher_plain(l2eigencalldemo, cipher1, num2)
  var result_number = await decrypt(l2eigencalldemo, result_cipher)

  expect(result_number).to.equal(num1 + num2)
  console.log(`add_cipher_plain ${num1} ${num2} is ${num1 + num2}`)
  ////////////////////////////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////////////////////////////
    // 'sub_cipher_cipher' test
    var num1 = 100
  var num2 = 1

  console.log(`Going to 'sub_cipher_cipher' ${num1}, ${num2}`)
  var cipher1 = ecies_encrypt(publicKey, num1)
  var cipher2 = ecies_encrypt(publicKey, num2)

  var result_cipher = await sub_cipher_cipher(l2eigencalldemo, cipher1, cipher2)
  var result_number = await decrypt(l2eigencalldemo, result_cipher)

  expect(result_number).to.equal(num1 - num2)
  console.log(`sub_cipher_cipher ${num1} ${num2} is ${num1 - num2}`)
  ////////////////////////////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////////////////////////////
    // 'sub_cipher_plain' test
    var num1 = 100
  var num2 = 1

  console.log(`Going to 'sub_cipher_plain' ${num1}, ${num2}`)
  var cipher1 = ecies_encrypt(publicKey, num1)

  var result_cipher = await sub_cipher_plain(l2eigencalldemo, cipher1, num2)
  var result_number = await decrypt(l2eigencalldemo, result_cipher)

  expect(result_number).to.equal(num1 - num2)
  console.log(`sub_cipher_plain ${num1} ${num2} is ${num1 - num2}`)
  ////////////////////////////////////////////////////////////////////////////////////

  console.log("All test success!")
}

main()
  .then(() => process.exit(0))
  .catch(error => {
    console.error(error)
    process.exit(1)
  })
