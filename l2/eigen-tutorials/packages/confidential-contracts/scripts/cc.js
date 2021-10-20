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

  let msg
  if (isNaN(num)) {
    msg = (new Uint64BE(num)).toBuffer()
  } else {
    msg = num.toBuffer()
  }
  const cipher = ecies.encrypt(public_key, msg, options);

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

  const l2cc = await (
    await ethers.getContractFactory('TestCCCustomToken')
  ).connect(l2Wallet)
  console.log('Deploying CCcontract to L2')
  const l2ccInstance = await l2cc.deploy({ gasLimit: 250000 })
  await l2ccInstance.deployed()
  console.log(`CC contract is deployed to ${l2ccInstance.address}`)

  const secret = "01234567891234560123456789123456";
  // balance
  let tx = await l2ccInstance.cipherBalanceOf(l2Wallet.address, secret, {
    gasPrice: 1,
    GasLimit: 25000,
  })
  let rec = await tx.wait();
  let event = rec.events.pop();
  let retValue = event.args.returnValue
  //decript
  let balance = ecies.aes_decrypt(key, retValue)
  expect(balance).to.eq(0)

  const receiver = (await hre.ethers.getSigners())[1]
  if (receiver === undefined) {
    throw new Error("receiver is empty")
  }
  //transfer
  const amount = 100;
  let cipher_amount = ecies_encrypt(public_key, amount);
  let tx = l2ccInstance.cipherTransfer(receiver, cipher_amount, {
    gasPrice: 1,
    gasLimit: 25000,
  })


  // balance
  let tx = await l2ccInstance.cipherBalanceOf(receiver, secret, {
    gasPrice: 1,
    GasLimit: 25000,
  })
  let rec = await tx.wait();
  let event = rec.events.pop();
  let retValue = event.args.returnValue
  //decript
  let balance = ecies.aes_decrypt(key, retValue)
  expect(balance).to.eq(amount)
}

main()
  .then(() => process.exit(0))
  .catch(error => {
    console.error(error)
    process.exit(1)
  })
