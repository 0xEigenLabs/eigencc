import { BigNumber, Wallet, providers, constants, utils } from "ethers";
import {
    Bridge,
    Inbox__factory,
    L2ToL1EventResult,
    DepositTokenEventResult,
    ArbTokenBridge__factory,
    EthERC20Bridge__factory,
    OutgoingMessageState,
} from 'arb-ts';
import { PayableOverrides } from '@ethersproject/contracts'

const { eigenLog, requireEnvVariables } = require('arb-shared-dependencies');
const deployments = require('../deployment.json');

import { TestCustomTokenL1 } from "../typechain/TestCustomTokenL1";
import { TestArbCustomToken } from "../typechain/TestArbCustomToken";
import { TestCustomTokenL1__factory } from '../typechain/factories/TestCustomTokenL1__factory';
import { TestArbCustomToken__factory } from '../typechain/factories/TestArbCustomToken__factory'

const hex2ascii = require('hex2ascii')

const MIN_APPROVAL = constants.MaxUint256

const wait = async (i: number) => {
    setTimeout(function() { console.log("Waiting") }, i);
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

const l1GasPrice = 1;
const gasLimit = 9646610
const maxGas = 9646610

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
    const res = await l1CustomToken.transfer(userAddr,
        BigNumber.from(1)
    );
    let rec = await res.wait();
    const data = await bridge.getAndUpdateL1TokenData(l1CustomToken.address);
    const userBalance = data?.ERC20?.balance
    console.log("l1 wallet balance : ", userBalance?.toString())

    let arbCustomToken: TestArbCustomToken
    const customTokenFactory2 = await new TestArbCustomToken__factory(l2TestWallet);
    console.log("deploy TestArbCustomToken");
    arbCustomToken = await customTokenFactory2.deploy(
        bridge.arbTokenBridge.address,
        l1CustomToken.address,
        { gasLimit: 800000, gasPrice: 1 }
    )
    await wait(10000)
    console.log("deploy TestArbCustomToken after deploy");
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

const registerTokenOnL2 = async (l1CustomTokenAddr: string, l2CustomTokenAddr: string) => {
    const l1CustomToken = TestCustomTokenL1__factory.connect(l1CustomTokenAddr, l1TestWallet);
    const arbCustomToken = TestArbCustomToken__factory.connect(l2CustomTokenAddr, l2TestWallet);
    console.log("registerTokenOnL2 on ", arbCustomToken.address);
    const registerRes = await l1CustomToken.registerTokenOnL2(
        arbCustomToken.address,
        BigNumber.from(599940),
        BigNumber.from(599940),
        BigNumber.from(10),
        l1TestWallet.address,
        { gasLimit: 599940, gasPrice: 10 }
    );
    const registerRec = await registerRes.wait();
    if (registerRec.status != 1) {
        throw new Error("registerTokenOnL2 failed")
    }
    const l2txhash = await bridge.getL2TxHashByRetryableTicket(registerRec)
    console.log("getL2TxHashByRetryableTicket", l2txhash)
    /*
    const activateCustomTokenEvents = await bridge.getActivateCustomTokenEventResult(
    	registerRec
    )
    console.log(activateCustomTokenEvents)
   */
    const seqNum = await bridge.getInboxSeqNumFromContractTransaction(registerRec)
    if (seqNum === undefined || seqNum.length <= 0) {
    	throw new Error("get seq num error")
    }
    return seqNum[0]
}

const deposit = async (l1CustomTokenAddr: string, tokenDepositAmount: BigNumber) => {
    let l1CustomToken: TestCustomTokenL1

    l1CustomToken = TestCustomTokenL1__factory.connect(l1CustomTokenAddr, ethProvider);
    const initialBridgeTokenBalance = await l1CustomToken.balanceOf(bridge.ethERC20Bridge.address);
    console.log("balance in l1 token", initialBridgeTokenBalance.toString());

    const initData = await bridge.getAndUpdateL2TokenData(l1CustomToken.address)
    const initCustomTokenData = initData?.CUSTOM

    const l2TokenAddr = await bridge.arbTokenBridge.functions
      .calculateL2TokenAddress(l1CustomToken.address)
      .then(([res]) => res)
    console.log("l2: ", l2TokenAddr)
	
    const l2AddressHopefully = await bridge.arbTokenBridge.customL2Token(
    	l1CustomToken.address
    )
    console.log("l2 hopefully: ", l2AddressHopefully)

    const data0 = await bridge.getAndUpdateL2TokenData(l1CustomToken.address)
    console.log(data0)
    const customTokenData0 = data0?.CUSTOM
    console.log("previous balance on L2", customTokenData0?.balance.toString())

    const depostiRes = await bridge.deposit(
        l1CustomToken.address,
        tokenDepositAmount, 
	{
		maxGas: BigNumber.from(maxGas), 
		gasPriceBid:BigNumber.from(1), 
		maxSubmissionPrice: BigNumber.from(1)
	}, 
	l1TestWallet.address,
        { gasLimit: 594949, gasPrice: l1GasPrice }
    );
    const depositRec = await depostiRes.wait();

    if (depositRec.status != 1) {
        throw new Error("despoit failed")
    }

    const finalBridgeTokenBalance = await l1CustomToken.balanceOf(
        bridge.ethERC20Bridge.address
    )
    console.log("finalBridgeTokenBalance", finalBridgeTokenBalance.toString())
    if (initialBridgeTokenBalance.add(tokenDepositAmount).eq(finalBridgeTokenBalance)) {
	console.log("deposit done");
    } else {
   	console.log("deposit failed", initialBridgeTokenBalance.toString(),
		   tokenDepositAmount.toString(),
		   finalBridgeTokenBalance.toString()) 
    }

    const tokenDepositData = (
        await bridge.getDepositTokenEventData(depositRec)
    )[0] as DepositTokenEventResult
    console.log("token deposit data", tokenDepositData)
    const seqNum = tokenDepositData.seqNum
    const retryableReceipt = await bridge.waitForRetriableReceipt(seqNum)
    if (retryableReceipt.status != 1) {
        throw new Error("waitForTransaction failed")
    }
    console.log("receipt", retryableReceipt);

    const afterBalance = await l1CustomToken.balanceOf(l1TestWallet.address);
    console.log("after balance in l1 token", afterBalance.toString());


    wait(10 * 1000)
    const data = await bridge.getAndUpdateL2TokenData(l1CustomToken.address)
    console.log(data)
    const customTokenData = data?.CUSTOM
    console.log("balance on L2", 
                (await customTokenData?.contract.balanceOf(l1TestWallet.address))?.toString(),
                customTokenData?.balance.toString(),
                initCustomTokenData?.balance.toString(),
                tokenDepositAmount.toString())
    
    const offset = customTokenData?.balance.sub(initCustomTokenData?.balance || 0);
    console.log("eq", offset?.toString(), tokenDepositAmount.toString())
    if (!offset?.eq(tokenDepositAmount)) {
        console.log("Invalid balance")
    	process.exit(-1);
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

const withdraw = async (l1CustomTokenAddr: string, arbCustomTokenAddr: string, tokenWithdrawAmount: BigNumber) => {
    console.log("Withdraw")
    const l2CustomToken = TestArbCustomToken__factory.connect(arbCustomTokenAddr, l2TestWallet)

    const initialBridgeTokenBalance = await l2CustomToken.balanceOf(l2TestWallet.address);
    console.log("balance in l2 token", initialBridgeTokenBalance?.toString());

    const l1CustomToken = TestCustomTokenL1__factory.connect(l1CustomTokenAddr, ethProvider);
    const initialBridgeTokenBalanceL1 = await l1CustomToken.balanceOf(bridge.ethERC20Bridge.address);
    console.log("balance in l1 token", initialBridgeTokenBalanceL1.toString());

    const withdrawRes = await l2CustomToken.withdraw(
        l1TestWallet.address,
        tokenWithdrawAmount,
        { gasLimit: 600000, gasPrice: 1 }
    )
    const withdrawRec = await withdrawRes.wait()
    console.log("withdraw done")
    const withdrawEventData = (
        await bridge.getWithdrawalsInL2Transaction(withdrawRec)
    )[0]
    console.log("withdraw data", withdrawEventData)

    const txHash = withdrawRec.transactionHash
    console.log("withdraw hash:", txHash)
    const initiatingTxnReceipt = await bridge.l2Provider.getTransactionReceipt(txHash);
    const outGoingMessagesFromTxn = await bridge.getWithdrawalsInL2Transaction(initiatingTxnReceipt)
    console.log(outGoingMessagesFromTxn)
    const { batchNumber, indexInBatch } = outGoingMessagesFromTxn[0]
    if (!batchNumber.eq(withdrawEventData.batchNumber) ||
        !indexInBatch.eq(withdrawEventData.indexInBatch)) {
        console.log("Invalid batchNumber or indexInBatch")
        process.exit(-1)
    }

    console.log("from outgoing msg", outGoingMessagesFromTxn[0])
    const outgoingMessageState = await bridge.getOutGoingMessageState(
        batchNumber,
        indexInBatch
    )
    /*
    // Should check, @IeigenHaimi
    if (!(outgoingMessageState === OutgoingMessageState.CONFIRMED)) {
        console.log("not confirmed")
        process.exit(-1)
    }
    */

    const receipt = await bridge.triggerL2ToL1Transaction(
        batchNumber,
        indexInBatch
    )
    if (receipt.status != 1) {
        console.log("trigger failed")
        process.exit(-1)
    }

    const curBridgeTokenBalance = await l2CustomToken.balanceOf(l2TestWallet.address);
    console.log("balance in l2 token", curBridgeTokenBalance?.toString());
    const offset = initialBridgeTokenBalance?.sub(curBridgeTokenBalance || 0);
    console.log("eq ", offset?.toString())
    if (!offset.eq(tokenWithdrawAmount)) {
        console.log("invalid withdraw")
        process.exit(-1);
    }
    const curTokenBalanceL1 = await l1CustomToken.balanceOf(bridge.ethERC20Bridge.address);
    console.log("balance in l1 token", curTokenBalanceL1.toString());
    const offset2 = curTokenBalanceL1?.sub(initialBridgeTokenBalanceL1 || 0);
    console.log("eq", offset2?.toString(), tokenWithdrawAmount.toString())
}

const getWalletBalance = async () => {
      const testWalletL1EthBalance = await bridge.getAndUpdateL1EthBalance()
      const testWalletL2EthBalance = await bridge.getAndUpdateL2EthBalance()
      console.log(testWalletL1EthBalance.toString(), testWalletL2EthBalance.toString())
      return [testWalletL1EthBalance, testWalletL2EthBalance]
}

const depositETH = async(ethToL2DepositAmount: BigNumber) => {
    const res2 = await bridge.depositETH(ethToL2DepositAmount, l1TestWallet.address)
    const rec2 = await res2.wait();
    console.log(rec2) 
    if (rec2.status != 1) {
    	throw new Error("Deposit l1 wallet error")
    }

    let bridgeEthBalance = await arbProvider.getBalance(deployments.ethERC20Bridge)
    console.log("deployments.ethERC20Bridge balance: ", bridgeEthBalance.toString()) 

    if (bridgeEthBalance.gt(BigNumber.from(0))) {
        console.log("Skip deposit ethERC20Bridge")
    }
    /*
    let balance = await getWalletBalance() 
    console.log(ethToL2DepositAmount.toString(), balance[1].toString())
    if (ethToL2DepositAmount.lt(balance[1])) {
    	return
    }
    */

    const res = await bridge.depositETH(ethToL2DepositAmount, deployments.ethERC20Bridge)	
    const rec = await res.wait();
    console.log(rec) 
    if (rec.status != 1) {
    	throw new Error("Deposit error")
    }
}

/*
const eigenCallDemo = async (
    arbCustomTokenAddr: string
) => {

    console.log("Withdraw")
    const l2CustomToken = TestArbCustomToken__factory.connect(arbCustomTokenAddr, l2TestWallet)
    // Here is example how we encrypt and descrypt
    const value = 123;

    const cipher = await l2CustomToken.encrypt(value);
    console.log("Encrypt the value: ", hex2ascii(cipher?.toString()));

    const plain = await l2CustomToken.decrypt(cipher?.toString());
    console.log("Decrypt the cipher:  ", hex2ascii(plain?.toString()));

    // Here is example how we compare cipher with cipher or plain
    const value_1 = 122;
    const value_2 = 123;
    const value_3 = 124;

    const cipher_1 = await l2CustomToken.encrypt(value_1);
    const cipher_2 = await l2CustomToken.encrypt(value_2);
    const cipher_3 = await l2CustomToken.encrypt(value_3);

    const result_cipher_cipher_1 = await l2CustomToken.compareCipherCipher(cipher, cipher_1); // 123 > 122, yields 1
    const result_cipher_cipher_2 = await l2CustomToken.compareCipherCipher(cipher, cipher_2); // 123 = 123, yields 0
    const result_cipher_cipher_3 = await l2CustomToken.compareCipherCipher(cipher, cipher_3); // 123 < 124, yields -1

    console.log("Compare cipher with cipher results: ", result_cipher_cipher_1, result_cipher_cipher_2, result_cipher_cipher_3)

    const result_cipher_plain_1 = await l2CustomToken.compareCipherPlain(cipher, value_1); // 123 > 122, yields 1
    const result_cipher_plain_2 = await l2CustomToken.compareCipherPlain(cipher, value_2); // 123 = 123, yields 0
    const result_cipher_plain_3 = await l2CustomToken.compareCipherPlain(cipher, value_3); // 123 < 124, yields -1

    console.log("Compare cipher with plain results: ", result_cipher_plain_1, result_cipher_plain_2, result_cipher_plain_3)

    // To get the cipher balance
    const curBridgeTokenCipherBalance = await l2CustomToken.cipherBalanceOf(l2TestWallet.address);
    console.log("cipher balance in l2 token", hex2ascii(curBridgeTokenCipherBalance?.toString()));
}
*/

const main = async () => {	
	/*
    const inboxAddr1 = await bridge.ethERC20Bridge.inbox()
    const receipt = await bridge.getL2Transaction(
	    '0xa7e4b50494bebca56aaa6d44b01fe9c9f92e358481794b82f16e13ad0259357e')
    
    console.log(receipt)

    return
    */

    await depositETH(utils.parseEther("1.0"))
    console.log("depositETH done")
    const inboxAddr = await bridge.ethERC20Bridge.inbox()
    console.log("Inbox: ", inboxAddr, deployments.inbox)

    let tokenPair = await deployL1AndL2()

    console.log(tokenPair)
    let seqNum = await registerTokenOnL2(tokenPair.l1CustomToken, tokenPair.l2CustomToken)
    console.log("seqNum", seqNum)

    const registerRec = await bridge.waitForRetriableReceipt(seqNum)
    console.log(registerRec)
    wait(15 * 1000)
    await approveToken(tokenPair.l1CustomToken)

    /*
    let tokenPair = {
      l1CustomToken: '0xceD8dFd4b63e8B035f3B05fb36398C70E2900262',
      l2CustomToken: '0x32D292d23A277410e23Ef29e79E2FD165FCD8F3E'
    }
    */
    const l2CustomToken = TestArbCustomToken__factory.connect(tokenPair.l2CustomToken, l2TestWallet)

    let amount = BigNumber.from(120000)
    await deposit(tokenPair.l1CustomToken, amount)
    await withdraw(tokenPair.l1CustomToken, tokenPair.l2CustomToken, amount)
}

main()
    .then(() => process.exit(0))
    .catch(error => {
        console.error(error)
        process.exit(1)
    })
