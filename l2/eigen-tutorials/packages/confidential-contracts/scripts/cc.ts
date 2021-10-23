import { BigNumber, Wallet, providers, constants, utils } from "ethers";
const { eigenLog, requireEnvVariables } = require('arb-shared-dependencies')
const RLP = require('rlp')
const { Base64 } = require('js-base64');
const { Uint64BE } = require("int64-buffer");
import fetch from "node-fetch"
const ecies = require('../../../../eigen_service/src/ecies')
const EC = require('elliptic').ec;
const ec = new EC('p256');
import { expect } from 'chai';

import { TestCCCustomToken__factory } from "../typechain/factories/TestCCCustomToken__factory"
import { TestCustomTokenL1 } from "../typechain/TestCustomTokenL1";
import { TestCCCustomToken } from "../typechain/TestCCCustomToken";
import { TestCustomTokenL1__factory } from '../typechain/factories/TestCustomTokenL1__factory';

import {
    Bridge,
    Inbox__factory,
    L2ToL1EventResult,
    DepositTokenEventResult,
    ArbTokenBridge__factory,
    EthERC20Bridge__factory,
    OutgoingMessageState,
} from 'arb-ts';

import {
    approveToken,
    depositETH,
    deposit,
    registerTokenOnL2
} from "./custom_token"

const deployments = require('../deployment.json');
require('dotenv').config()
const wait = async (i: number) => {
    setTimeout(function() { console.log("Waiting") }, i);
}

requireEnvVariables(['DEVNET_PRIVKEY', 'L2RPC', 'PKCS'])

const ethProvider = new providers.JsonRpcProvider(process.env.L1RPC)
const arbProvider = new providers.JsonRpcProvider(process.env.L2RPC)
const testSk = process.env.DEVNET_PRIVKEY || ""
const l1TestWallet = new Wallet(testSk, ethProvider);
const l2TestWallet = new Wallet(testSk, arbProvider);
const receiver = "0xD73EbFad38707CB2AB4D127A43A193Bc526F5151"

const bridge = new Bridge(
    deployments.ethERC20Bridge,
    deployments.arbTokenBridge,
    l1TestWallet,
    l2TestWallet
)

const l1GasPrice = 1;
const gasLimit = 9646610
const maxGas = 9646610

const symmetricCypherName = 'aes-256-gcm'

const deployL1AndL2 = async () => {
    let l1CustomToken: TestCustomTokenL1
    console.log("pre funded balance", (await l1TestWallet.getBalance()).toString());

    const customTokenFactory = await new TestCustomTokenL1__factory(l1TestWallet);
    l1CustomToken = await customTokenFactory.deploy(
        bridge.ethERC20Bridge.address
    )
    await wait(10000)

    console.log("L1 custom address", l1CustomToken.address);
    const mintRes = await l1CustomToken.mint();
    const minRec = await mintRes.wait()
    const bal = await l1CustomToken.balanceOf(l1TestWallet.address);
    console.log("l1 wallet balance in token", bal.toString());
    const res = await l1CustomToken.transfer(receiver,
        BigNumber.from(1)
    );
    let rec = await res.wait();
    const data = await bridge.getAndUpdateL1TokenData(l1CustomToken.address);
    const userBalance = data?.ERC20?.balance
    console.log("l1 wallet balance : ", userBalance?.toString())

    let arbCustomToken: TestCCCustomToken
    const customTokenFactory2 = await new TestCCCustomToken__factory(l2TestWallet);
    console.log("deploy TestCCCustomToken");
    arbCustomToken = await customTokenFactory2.deploy(
        bridge.arbTokenBridge.address,
        l1CustomToken.address,
        { gasLimit: 60000000, gasPrice: 1 }
    )
    await wait(10000)
    console.log("deploy TestCCCustomToken after deploy");
    rec = await arbCustomToken.deployTransaction.wait()
    if (rec.status != 1) {
        throw new Error("deployTransaction failed")
    }

    await arbCustomToken.deployed()
    console.log("L2 custom address", arbCustomToken.address,
        arbCustomToken.deployTransaction.hash);

    await (1000000)
    return { l1CustomToken: l1CustomToken.address, l2CustomToken: arbCustomToken.address }
}

function ecies_encrypt(public_key: any, num: any) {
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
    msg = num
  }
  const cipher = ecies.encrypt(public_key, msg, options);

  return cipher
}

const main = async () => {
  await eigenLog('Simple Confidential Contract Demo')

  const response = await fetch(process.env['PKCS'] + '/store?digest=1', {
    method: 'GET',
    headers: { 'Content-Type': 'application/json' }
  });
  const res: any = await response.json()

  expect(res.errno).to.equal(0)

  const public_key = res.data.public_key

  console.log("Public key get from pkcs: ", public_key)

  expect(public_key).not.equal("")

  let keyPair = ec.keyFromPublic(public_key, "hex");
  let publicKey = keyPair.getPublic();

  console.log("----------------------------------------------------")

  await depositETH(utils.parseEther("10"))

  const tokenPair = await deployL1AndL2()
  console.log(tokenPair)

  let seqNum = await registerTokenOnL2(tokenPair.l1CustomToken, tokenPair.l2CustomToken)
  console.log("seqNum", seqNum)

  const registerRec = await bridge.waitForRetriableReceipt(seqNum)
  console.log(registerRec)
  wait(15 * 1000)
  await approveToken(tokenPair.l1CustomToken)

  let amountDeposit = BigNumber.from(120000)
  await deposit(tokenPair.l1CustomToken, amountDeposit)

  const secret = "01234567891234560123456789123456";
  const cipherSecret = Base64.encode(ecies_encrypt(publicKey, secret));
  console.log("cipher secret", cipherSecret)
  // balance
  const l2ccInstance = TestCCCustomToken__factory.connect(tokenPair.l2CustomToken, l2TestWallet);
  let tx = await l2ccInstance.cipherBalanceOf(l2TestWallet.address, Buffer.from(cipherSecret), {
    gasPrice: 1,
    gasLimit: 25000,
  })
  console.log("cipher balance in l2 token", Base64.decode(tx?.toString()));
  //decript
  let balance = ecies.aes_dec(symmetricCypherName, secret, Base64.decode(tx?.toString()))
  expect(balance).to.eq(0)

  //transfer
  const amount = 100;
  let cipher_amount = Base64.encode(ecies_encrypt(public_key, amount));
  let transferTx = l2ccInstance.cipherTransfer(receiver, cipher_amount, {
    gasPrice: 1,
    gasLimit: 25000,
  })

  // balance
  tx = await l2ccInstance.cipherBalanceOf(receiver, Buffer.from(cipherSecret), {
    gasPrice: 1,
    gasLimit: 25000,
  })
  console.log("cipher balance in l2 token", Base64.decode(tx?.toString()));
  //decript
  balance = ecies.aes_dec(symmetricCypherName, secret, Base64.decode(tx?.toString()))
  expect(balance).to.eq(amount)
}

main()
  .then(() => process.exit(0))
  .catch(error => {
    console.error(error)
    process.exit(1)
  })