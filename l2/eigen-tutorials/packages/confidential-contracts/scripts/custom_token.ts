import { BigNumber, Wallet, providers, constants, utils } from "ethers";
import {
    Bridge,
    DepositTokenEventResult,
    OutgoingMessageState,
} from 'arb-ts';
import { PayableOverrides } from '@ethersproject/contracts'

const { eigenLog, requireEnvVariables } = require('arb-shared-dependencies');
const deployments = require('../deployment.json');

import { TestCustomTokenL1 } from "../typechain/TestCustomTokenL1";
import { TestArbCustomToken } from "../typechain/TestArbCustomToken";
import { TestCustomTokenL1__factory } from '../typechain/factories/TestCustomTokenL1__factory';
import { TestArbCustomToken__factory } from '../typechain/factories/TestArbCustomToken__factory'

const MIN_APPROVAL = constants.MaxUint256

require('dotenv').config()
requireEnvVariables(['DEVNET_PRIVKEY', 'L2RPC', 'L1RPC'])

import {
    wait,
    approveToken,
    depositETH,
    deposit,
    withdraw,
    deployL1AndL2,
    registerTokenOnL2
} from "./common"

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

const main = async () => {	

    await depositETH(bridge, l1TestWallet, l2TestWallet, utils.parseEther("1.0"))
    console.log("depositETH done")
    const inboxAddr = await bridge.ethERC20Bridge.inbox()
    console.log("Inbox: ", inboxAddr, deployments.inbox)

    let tokenPair = await deployL1AndL2(bridge, l1TestWallet, l2TestWallet)

    console.log(tokenPair)
    let seqNum = await registerTokenOnL2(bridge, l1TestWallet, l2TestWallet, tokenPair.l1CustomToken, tokenPair.l2CustomToken)
    console.log("seqNum", seqNum)

    const registerRec = await bridge.waitForRetriableReceipt(seqNum)
    console.log(registerRec)
    wait(15 * 1000)
    await approveToken(bridge, l1TestWallet, l2TestWallet, tokenPair.l1CustomToken)

    const l2CustomToken = TestArbCustomToken__factory.connect(tokenPair.l2CustomToken, l2TestWallet)

    let amount = BigNumber.from(1200000)
    let amount2 = BigNumber.from(120000)
    await deposit(bridge, l1TestWallet, l2TestWallet, tokenPair.l1CustomToken, amount)
    await withdraw(bridge, l1TestWallet, l2TestWallet, tokenPair.l1CustomToken, tokenPair.l2CustomToken, amount2)
}

main()
    .then(() => process.exit(0))
    .catch(error => {
        console.error(error)
        process.exit(1)
    })
