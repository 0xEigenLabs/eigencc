import { BigNumber, Wallet, providers, constants } from "ethers";
import {
  Bridge,
  L2ToL1EventResult,
  DepositTokenEventResult,
  ArbTokenBridge__factory,
  EthERC20Bridge__factory,
} from 'arb-ts';
import { PayableOverrides } from '@ethersproject/contracts'

const { eigenLog, requireEnvVariables } = require('arb-shared-dependencies');
const deployments = require('../deployment.json');

import { TestCustomTokenL1 } from "../typechain/TestCustomTokenL1";
import { TestArbCustomToken } from "../typechain/TestArbCustomToken";
import { TestCustomTokenL1__factory } from '../typechain/factories/TestCustomTokenL1__factory';
import { TestArbCustomToken__factory } from '../typechain/factories/TestArbCustomToken__factory'

const MIN_APPROVAL = constants.MaxUint256

interface ActivateCustomTokenResult {
  seqNum: BigNumber
  l1Addresss: string
  l2Address: string
}

const wait = async (i: number) => {
    setTimeout(function(){ console.log("Waiting")}, i);
}

require('dotenv').config()
requireEnvVariables(['DEVNET_PRIVKEY', 'L2RPC', 'L1RPC'])

const ethProvider = new providers.JsonRpcProvider(process.env.L1RPC)
const arbProvider = new providers.JsonRpcProvider(process.env.L2RPC)
const testSk = process.env.DEVNET_PRIVKEY || ""
const l1TestWallet = new Wallet(testSk, ethProvider);
const l2TestWallet = new Wallet(testSk, arbProvider);
const userAddr = "0xD73EbFad38707CB2AB4D127A43A193Bc526F5151"

const bridge = new Bridge(
  deployments.ethERC20Bridge,
  deployments.arbTokenBridge,
  l1TestWallet,
  l2TestWallet
)
const l1GasPrice = 10;
const gasLimit = 9646610
const maxGas = 9646610

const deploy_l1 = async () => {
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
 const res = await l1CustomToken.transfer(userAddr,
      BigNumber.from(200)
 );
 let rec = await res.wait();
 const data = await bridge.getAndUpdateL1TokenData(l1CustomToken.address);
 const userBalance = data?.ERC20?.balance
 console.log("l1 wallet balance : ", userBalance?.toString())
 return l1CustomToken.address
}

const deploy_l2 = async (l1CustomTokenAddr:string) => {
 let arbCustomToken: TestArbCustomToken
 const customTokenFactory = await new TestArbCustomToken__factory(l2TestWallet);
 console.log("deploy TestArbCustomToken");
 arbCustomToken = await customTokenFactory.deploy(
    bridge.arbTokenBridge.address,
    l1CustomTokenAddr,
    {gasLimit: 9646610, gasPrice: 0}
 )
 await wait(10000)
 let rec = await arbCustomToken.deployTransaction.wait()
 if (rec.status != 1) {
     throw new Error("deployTransaction failed")
 }
 console.log("L2 custom address", arbCustomToken.address);
 let l1CustomToken = TestCustomTokenL1__factory.connect(l1CustomTokenAddr, ethProvider);
 const registerRes = await l1CustomToken.registerTokenOnL2(
     arbCustomToken.address,
     BigNumber.from(maxGas),
     BigNumber.from(maxGas),
     BigNumber.from(0),
     l1TestWallet.address,
     {gasLimit: gasLimit}
 ); 
 const registerRec = await registerRes.wait();
 if (registerRec.status != 1) {
     throw new Error("registerTokenOnL2 failed")
 }
 const factory = new EthERC20Bridge__factory();
 const contract = factory.attach(l1CustomTokenAddr);
 const iface = contract.interface
 const event = iface.getEvent('ActivateCustomToken')
 const eventTopic = iface.getEventTopic(event);
    const logs = registerRec.logs.filter(log => {
        return log.topics[0] == eventTopic
    })
  const result = await logs.map(log => (iface.parseLog(log).args as unknown) as ActivateCustomTokenResult)
  const {seqNum} = result[0]
 const l2RetryableHash = await bridge.calculateL2RetryableTransactionHash(
   seqNum
 )
 const retrableReceipt = await arbProvider.waitForTransaction(l2RetryableHash);

 return arbCustomToken.address
}

const deposit = async (l1CustomTokenAddr: string, tokenDepositAmount: BigNumber) => {
 let l1CustomToken: TestCustomTokenL1
 let arbCustomToken: TestArbCustomToken

 l1CustomToken = TestCustomTokenL1__factory.connect(l1CustomTokenAddr, ethProvider);
 const initialBridgeTokenBalance = await l1CustomToken.balanceOf(userAddr);
 console.log("balance in l1 token", initialBridgeTokenBalance);

 const depostiRes = await bridge.deposit(l1CustomToken.address, tokenDepositAmount, {}, undefined, {gasLimit: 210000, gasPrice: l1GasPrice});
 const depositRec = await depostiRes.wait(); 

    if (depositRec.status != 1) {
        throw new Error("despoit failed")
    }

    const finalBridgeTokenBalance = await l1CustomToken.balanceOf(
      bridge.ethERC20Bridge.address
    )
    const tokenDepositData = (
        await bridge.getDepositTokenEventData(depositRec)
    )[0] as DepositTokenEventResult
    const seqNum = tokenDepositData.seqNum
    const l2RetryableHash = await bridge.calculateL2TransactionHash(seqNum);
    const retrableReceipt = await arbProvider.waitForTransaction(l2RetryableHash)
    if (retrableReceipt.status != 1) {
        throw new Error("waitForTransaction failed")
    }
}

const approveToken = async (
  erc20L1Address: string
) => {
    const approveRes = await bridge.approveToken(erc20L1Address)
    const approveRec = await approveRes.wait()
    if (approveRec.status != 1) {
        throw new Error('approve error')
    }
    const data = await bridge.getAndUpdateL1TokenData(erc20L1Address)
    const allowed = data.ERC20 && data.ERC20.allowed
    console.log("approve ", allowed)
}

const withdraw = async(arbCustomTokenAddr: string, tokenWithdrawAmount: BigNumber) => {
    const l2CustomToken = TestArbCustomToken__factory.connect(arbCustomTokenAddr, l2TestWallet)

    const withdrawRes = await l2CustomToken.withdraw(
      l1TestWallet.address,
      tokenWithdrawAmount,
      { gasLimit: gasLimit }
    )
    const withdrawRec = await withdrawRes.wait()
    const withdrawEventData = (
      await bridge.getWithdrawalsInL2Transaction(withdrawRec)
    )[0]
    const outGoingMessages: L2ToL1EventResult[] = []
    outGoingMessages.push(withdrawEventData)
    console.log(outGoingMessages)
}

const main = async() => {
    let l1CustomTokenAddr = await deploy_l1()
    await approveToken(l1CustomTokenAddr)
    let l2CustomTokenAddr = await deploy_l2(l1CustomTokenAddr)
    let amount = BigNumber.from(100)
    deposit(l1CustomTokenAddr, amount)
    withdraw(l2CustomTokenAddr, amount)
}

main()
  .then(() => process.exit(0))
  .catch(error => {
    console.error(error)
    process.exit(1)
  })
