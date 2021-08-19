const { ethers } = require('hardhat')
const { expect } = require('chai')
const { arbLog, requireEnvVariables } = require('arb-shared-dependencies')
var RLP = require('rlp')
var BASE64 = require('Base64')

require('dotenv').config()

requireEnvVariables(['DEVNET_PRIVKEY', 'L2RPC'])

function compose_decrypt(cipher) {
  return RLP.encode(["decrypt", BASE64.atob(cipher), "", ""])
}

function compose_encrypt(num) {
  return RLP.encode(["encrypt", num.toString(), "", ""])
}

function compose_add_cipher_cipher(cipher1, cipher2) {
  return RLP.encode(["add_cipher_cipher", BASE64.atob(cipher1),  BASE64.atob(cipher2), ""])
}

function compose_add_cipher_plain(cipher, plain) {
  return RLP.encode(["add_cipher_plain", BASE64.atob(cipher),  plain.toString(), ""])
}

function compose_sub_cipher_cipher(cipher1, cipher2) {
  return RLP.encode(["sub_cipher_cipher", BASE64.atob(cipher1),  BASE64.atob(cipher2), ""])
}

function compose_sub_cipher_plain(cipher, plain) {
  return RLP.encode(["sub_cipher_plain", BASE64.atob(cipher),  plain.toString(), ""])
}

const encrypt = async (contract, num) => {
  var encrypt_operator_encoding_string =  compose_encrypt(num)
  var tx = await contract.call_eigenCall(encrypt_operator_encoding_string, {
    gasPrice: 0,
    gasLimit: 250000
  })

  var receipt = await tx.wait()
  var event = receipt.events.pop()

  rlp_encoded_return_value = event.args.returnValue;

  expect(rlp_encoded_return_value).not.equal(RLP.encode(""))
  
  var cipher_base64 = RLP.decode(rlp_encoded_return_value)
  var cipher = BASE64.btoa(cipher_base64)
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

  var plain = RLP.decode(rlp_encoded_return_value)

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

  var cipher_base64 = RLP.decode(rlp_encoded_return_value)
  var cipher = BASE64.btoa(cipher_base64)
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

  var cipher_base64 = RLP.decode(rlp_encoded_return_value)
  var cipher = BASE64.btoa(cipher_base64)
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

  var cipher_base64 = RLP.decode(rlp_encoded_return_value)
  var cipher = BASE64.btoa(cipher_base64)
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

  var cipher_base64 = RLP.decode(rlp_encoded_return_value)
  var cipher = BASE64.btoa(cipher_base64)
  return cipher
}


const main = async () => {
  await arbLog('Simple eigenCall demo')

  const l2Wallet = (await hre.ethers.getSigners())[0]
  console.log('Your wallet address:', l2Wallet.address)

  const L2EigencallDemo = await (
    await ethers.getContractFactory('EigencallDemo')
  ).connect(l2Wallet)
  console.log('Deploying EigencallDemo contract to L2')
  const l2eigencalldemo = await L2EigencallDemo.deploy({gasLimit: 250000})
  await l2eigencalldemo.deployed()
  console.log(`EigencallDemo contract is deployed to ${l2eigencalldemo.address}`)

  ////////////////////////////////////////////////////////////////////////////////////
  // 'encrypt' test
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
  var cipher1 = await encrypt(l2eigencalldemo, num1)
  var cipher2 = await encrypt(l2eigencalldemo, num2)

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
  var cipher1 = await encrypt(l2eigencalldemo, num1)

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
  var cipher1 = await encrypt(l2eigencalldemo, num1)
  var cipher2 = await encrypt(l2eigencalldemo, num2)

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
  var cipher1 = await encrypt(l2eigencalldemo, num1)

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
