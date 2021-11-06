const { ethers } = require('hardhat')
const { expect } = require('chai')
const { eigenLog, requireEnvVariables } = require('arb-shared-dependencies')
const { Uint64BE } = require('int64-buffer')
const fetch = require('node-fetch')
const ecies = require('./ecies')
const EC = require('elliptic').ec
const ec = new EC('p256')
const hex2ascii = require('hex2ascii')

require('dotenv').config()

requireEnvVariables(['DEVNET_PRIVKEY', 'L2RPC', 'PKCS'])

const demo_eigencall_encrypt = async (contract, num) => {
  console.log(
    'Going to call `demo_encrypt` which calls the `EigenCallLibcary.encrypt` with number: ',
    num
  )
  var cipher_hex = await contract.demo_encrypt(num, {
    gasPrice: 0,
    gasLimit: 250000,
  })

  console.log(cipher_hex, hex2ascii(cipher_hex))
  return hex2ascii(cipher_hex)
}

const demo_eigencall_decrypt = async (contract, cipher) => {
  console.log(
    'Going to call `demo_decrypt` which calls the `EigenCallLibcary.decrypt` with cipher: ',
    cipher
  )
  var num_string = await contract.demo_decrypt(cipher, {
    gasPrice: 0,
    gasLimit: 250000,
  })

  return hex2ascii(num_string)
}

const demo_eigencall_add_cipher_cipher = async (contract, cipher1, cipher2) => {
  console.log(
    'Going to call `demo_add_cipher_cipher` which calls the `EigenCallLibcary.demo_addCipherCipher` with ciphers: ',
    cipher1,
    ', ',
    cipher2
  )

  var cipher_hex = await contract.demo_addCipherCipher(cipher1, cipher2, {
    gasPrice: 0,
    gasLimit: 250000,
  })

  return hex2ascii(cipher_hex)
}

const demo_eigencall_add_cipher_plain = async (contract, cipher, num) => {
  console.log(
    'Going to call `demo_eigencall_add_cipher_plain` which calls the `EigenCallLibcary.demo_addCipherPlain` with: ',
    cipher,
    ', ',
    num
  )

  var cipher_hex = await contract.demo_addCipherPlain(cipher, num, {
    gasPrice: 0,
    gasLimit: 250000,
  })

  return hex2ascii(cipher_hex)
}

const demo_eigencall_sub_cipher_cipher = async (contract, cipher1, cipher2) => {
  console.log(
    'Going to call `demo_sub_cipher_cipher` which calls the `EigenCallLibcary.demo_subCipherCipher` with ciphers: ',
    cipher1,
    ', ',
    cipher2
  )

  var cipher_hex = await contract.demo_subCipherCipher(cipher1, cipher2, {
    gasPrice: 0,
    gasLimit: 250000,
  })

  return hex2ascii(cipher_hex)
}

const demo_eigencall_sub_cipher_plain = async (contract, cipher, num) => {
  console.log(
    'Going to call `demo_sub_cipher_plain` which calls the `EigenCallLibcary.demo_subCipherPlain` with: ',
    cipher,
    ', ',
    num
  )

  var cipher_hex = await contract.demo_subCipherPlain(cipher, num, {
    gasPrice: 0,
    gasLimit: 250000,
  })

  return hex2ascii(cipher_hex)
}

const demo_eigencall_compare_cipher_cipher = async (
  contract,
  cipher1,
  cipher2
) => {
  console.log(
    'Going to call `demo_compare_cipher_cipher` which calls the `EigenCallLibcary.demo_compareCipherCipher` with ciphers: ',
    cipher1,
    ', ',
    cipher2
  )

  var result = await contract.demo_compareCipherCipher(cipher1, cipher2, {
    gasPrice: 0,
    gasLimit: 250000,
  })

  console.log('Result: ', result)

  return result
}

const demo_eigencall_compare_cipher_plain = async (contract, cipher, num) => {
  console.log(
    'Going to call `demo_compare_cipher_plain` which calls the `EigenCallLibcary.demo_compareCipherPlain` with: ',
    cipher,
    ', ',
    num
  )

  var result = await contract.demo_compareCipherPlain(cipher, num, {
    gasPrice: 0,
    gasLimit: 250000,
  })

  return result
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
    s2: null, // optional shared information2
  }
  let msg = new Uint64BE(num).toBuffer()
  return ecies.encrypt(public_key, msg, options).toString('hex')
}

const main = async () => {
  await eigenLog('Simple eigenCall demo')

  const res = await fetch(process.env['PKCS'] + '/store?digest=1', {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
    },
  }).then(response => response.json())

  expect(res.errno).to.equal(0)

  const public_key = res.data.public_key

  console.log('Public key get from pkcs: ', public_key)

  expect(public_key).not.equal('')

  let keyPair = ec.keyFromPublic(public_key, 'hex')
  let publicKey = keyPair.getPublic()

  console.log('----------------------------------------------------')

  const l2Wallet = (await hre.ethers.getSigners())[0]
  console.log('Your wallet address:', l2Wallet.address)
  /////////////////////////////////////////////////////////////////////////
  var L2EigenCallLibrary = await (
    await ethers.getContractFactory('EigenCallLibrary')
  ).connect(l2Wallet)
  L2EigenCallLibrary = await L2EigenCallLibrary.deploy()
  await L2EigenCallLibrary.deployed()
  console.log(
    'EigenCallLibrary is deployed at address:',
    L2EigenCallLibrary.address
  )

  var L2EigenCallLibraryUseDemo = await (
    await ethers.getContractFactory('EigenCallLibraryUseDemo', {
      libraries: {
        EigenCallLibrary: L2EigenCallLibrary.address,
      },
    })
  ).connect(l2Wallet)

  console.log('Deploying EigenCallLibraryUseDemo contract to L2')
  L2EigenCallLibraryUseDemo = await L2EigenCallLibraryUseDemo.deploy({
    gasLimit: 25000000,
  })
  await L2EigenCallLibraryUseDemo.deployed()
  console.log(
    `EigencallDemo contract is deployed to ${L2EigenCallLibraryUseDemo.address}`
  )
  console.log('----------------------------------------------------')
  var num = 123
  var cipher_num = await demo_eigencall_encrypt(L2EigenCallLibraryUseDemo, num)

  console.log(`${num} is encrypted as '${cipher_num}'`)
  console.log('----------------------------------------------------')

  var num = 100
  var cipher_num = ecies_encrypt(publicKey, num)
  console.log(`Going to decrypt '${cipher_num}'`)

  var decrypted_num = await demo_eigencall_decrypt(
    L2EigenCallLibraryUseDemo,
    Buffer.from(cipher_num)
  )

  console.log(`${cipher_num} is decrypted as '${decrypted_num}'`)
  console.log('----------------------------------------------------')

  var num1 = 100
  var cipher1_num = ecies_encrypt(publicKey, num1)

  var num2 = 1
  var cipher2_num = ecies_encrypt(publicKey, num2)

  var add_cipher_cipher_result = await demo_eigencall_add_cipher_cipher(
    L2EigenCallLibraryUseDemo,
    Buffer.from(cipher1_num),
    Buffer.from(cipher2_num)
  )

  console.log(
    `Add 2 ciphers: ${cipher1_num}, ${cipher2_num} '${add_cipher_cipher_result}'`
  )

  var decrypted_num = await demo_eigencall_decrypt(
    L2EigenCallLibraryUseDemo,
    Buffer.from(add_cipher_cipher_result)
  )
  console.log(`And the result is the cipher of '${decrypted_num}'`)

  console.log('----------------------------------------------------')

  var cipher_num = ecies_encrypt(publicKey, 100)

  var num = 1

  var add_cipher_plain_result = await demo_eigencall_add_cipher_plain(
    L2EigenCallLibraryUseDemo,
    Buffer.from(cipher_num),
    num
  )

  console.log(
    `Add cipher with a number: ${cipher_num}, ${num} '${add_cipher_plain_result}'`
  )

  var decrypted_num = await demo_eigencall_decrypt(
    L2EigenCallLibraryUseDemo,
    Buffer.from(add_cipher_plain_result)
  )
  console.log(`And the result is the cipher of '${decrypted_num}'`)

  console.log('----------------------------------------------------')

  var num1 = 100
  var cipher1_num = ecies_encrypt(publicKey, num1)

  var num2 = 1
  var cipher2_num = ecies_encrypt(publicKey, num2)

  var sub_cipher_cipher_result = await demo_eigencall_sub_cipher_cipher(
    L2EigenCallLibraryUseDemo,
    Buffer.from(cipher1_num),
    Buffer.from(cipher2_num)
  )

  console.log(
    `Sub 2 ciphers: ${cipher1_num}, ${cipher2_num} '${sub_cipher_cipher_result}'`
  )

  var decrypted_num = await demo_eigencall_decrypt(
    L2EigenCallLibraryUseDemo,
    Buffer.from(sub_cipher_cipher_result)
  )
  console.log(`And the result is the cipher of '${decrypted_num}'`)

  console.log('----------------------------------------------------')

  var cipher_num = ecies_encrypt(publicKey, 100)

  var num = 1

  var sub_cipher_plain_result = await demo_eigencall_sub_cipher_plain(
    L2EigenCallLibraryUseDemo,
    Buffer.from(cipher_num),
    num
  )

  console.log(
    `Sub cipher with a number: ${cipher_num}, ${num} '${sub_cipher_plain_result}'`
  )

  var decrypted_num = await demo_eigencall_decrypt(
    L2EigenCallLibraryUseDemo,
    Buffer.from(sub_cipher_plain_result)
  )
  console.log(`And the result is the cipher of '${decrypted_num}'`)

  console.log('----------------------------------------------------')

  var num1 = 100
  var cipher1_num = ecies_encrypt(publicKey, num1)

  var num2 = 101
  var cipher2_num = ecies_encrypt(publicKey, num2)

  var compare_cipher_cipher_result = await demo_eigencall_compare_cipher_cipher(
    L2EigenCallLibraryUseDemo,
    Buffer.from(cipher1_num),
    Buffer.from(cipher2_num)
  )

  console.log(
    `Compare 2 ciphers: ${cipher1_num}, ${cipher2_num} '${compare_cipher_cipher_result}'`
  )

  console.log('----------------------------------------------------')

  var cipher_num = ecies_encrypt(publicKey, 100)

  var num = 101

  var compare_cipher_plain_result = await demo_eigencall_compare_cipher_plain(
    L2EigenCallLibraryUseDemo,
    Buffer.from(cipher_num),
    num
  )

  console.log(
    `Compare cipher with a number: ${cipher_num}, ${num} '${compare_cipher_plain_result}'`
  )

  console.log('----------------------------------------------------')
}

main()
  .then(() => process.exit(0))
  .catch(error => {
    console.error(error)
    process.exit(1)
  })
