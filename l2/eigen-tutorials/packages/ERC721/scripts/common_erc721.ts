import { ContractReceipt, Signer, BigNumber, Wallet, providers, constants, utils, ethers} from "ethers";

import { PayableOverrides } from '@ethersproject/contracts'

const { eigenLog, requireEnvVariables } = require('arb-shared-dependencies');
const deployments = require('../deployment.json');

import { ERC721__factory } from "../typechain/factories/ERC721__factory"
import { ERC721 } from "../typechain/ERC721"

import { EthERC721Bridge__factory } from "../typechain/factories/EthERC721Bridge__factory"
import { ArbTokenBridge__factory } from "../typechain/factories/ArbTokenBridge__factory"
import { EthERC721Bridge } from "../typechain/EthERC721Bridge"
import { ArbTokenBridge } from "../typechain/ArbTokenBridge"
import { StandardArbERC721 } from "../typechain/StandardArbERC721"
import { StandardArbERC721__factory } from "../typechain/factories/StandardArbERC721__factory"

import { ICustomToken721 } from "../typechain/ICustomToken721"
import { ICustomToken721__factory } from "../typechain/factories/ICustomToken721__factory"

import { TestCustomToken721L1 } from "../typechain/TestCustomToken721L1";
import { TestArbCustomToken721 } from "../typechain/TestArbCustomToken721";
import { TestCustomToken721L1__factory } from '../typechain/factories/TestCustomToken721L1__factory';
import { TestArbCustomToken721__factory } from '../typechain/factories/TestArbCustomToken721__factory'

export const wait = async (ms: number) => {
    setTimeout(function() { console.log("Waiting") }, ms);
}

import {
    Bridge,
    DepositTokenEventResult,
    OutgoingMessageState,
} from 'arb-ts';

const l1GasPrice = 1;
const l1GasLimit = 599940
const gasLimit = 9646610
const maxGas = 9646610
const userAddr = "0x81183C9C61bdf79DB7330BBcda47Be30c0a85064"
export type ChainIdOrProvider = BigNumber | providers.Provider
export const addressToSymbol = (erc721L1Address: string) => {
  return erc721L1Address.substr(erc721L1Address.length - 3).toUpperCase() + '?'
}

export interface L1TokenData {
    ERC721?: {
        contract: ERC721
        balance: BigNumber
        symbol: string
        name: string
    }

    CUSTOM?: {
        contract: ERC721
        balance: BigNumber
        symbol: string
    }
}

export interface L2TokenData {
    ERC721?: { contract: StandardArbERC721; balance: BigNumber }
    CUSTOM?: { contract: ICustomToken721; balance: BigNumber }
}

export interface Tokens {
  [contractAddress: string]: L1TokenData | L2TokenData | undefined
}

export class EigBridge {
    ethTokenBridge: EthERC721Bridge
    arbTokenBridge: ArbTokenBridge
    bridge: Bridge
    l1Tokens: Tokens
    l2Tokens: Tokens

    constructor(
        ethBridge: string,
        arbBridge: string,
        ethSigner: Signer,
        arbSigner: Signer
    ) {
        this.bridge = new Bridge(ethBridge, arbBridge, ethSigner, arbSigner)
        this.ethTokenBridge = EthERC721Bridge__factory.connect(ethBridge, ethSigner)
        this.arbTokenBridge = ArbTokenBridge__factory.connect(arbBridge, arbSigner)
        this.l1Tokens = {}
        this.l2Tokens = {}
    }

    public async getAndUpdateL1TokenData(erc721L1Address: string) {
        const tokenData = this.l1Tokens[erc721L1Address] || {
            ERC721: undefined,
            CUSTOM: undefined,
        }
        this.l1Tokens[erc721L1Address] = tokenData
        const walletAddress = await this.bridge.getWalletAddress()

        if (!tokenData.ERC721) {
            if ((await this.ethTokenBridge.provider.getCode(erc721L1Address)).length > 2) {
                // If this will throw if not an ERC20, which is what we *want*.
                const ethERC20TokenContract = await ERC721__factory.connect(
                    erc721L1Address,
                    this.ethTokenBridge.signer
                )
                const [balance] = await ethERC20TokenContract.functions.balanceOf(
                    walletAddress
                )

                // non-standard
                const symbol = await ethERC20TokenContract.functions
                .symbol()
                .then(([res]) => res)
                .catch(_ => addressToSymbol(erc721L1Address))

                const name = await ethERC20TokenContract.functions
                .name()
                .then(([res]) => res)
                .catch(_ => symbol + '_Token')

                //const allowed = await allowance.gte(MIN_APPROVAL.div(2))
                tokenData.ERC721 = {
                    contract: ethERC20TokenContract,
                    balance,
                    symbol,
                    name,
                }
            } else {
                throw new Error(`No ERC20 at ${erc721L1Address} `)
            }
        } else {
            const ethERC20TokenContract = await ERC721__factory.connect(
                erc721L1Address,
                this.ethTokenBridge.signer
            )
            const [balance] = await ethERC20TokenContract.functions.balanceOf(
                walletAddress
            )
            tokenData.ERC721.balance = balance
        }

        return tokenData
    }

    public getERC20L2Address(erc721L1Address: string) {
        let address: string | undefined
        if ((address = this.l2Tokens[erc721L1Address]?.ERC721?.contract.address)) {
            return address
        }
        return this.arbTokenBridge.functions
        .calculateL2TokenAddress(erc721L1Address)
        .then(([res]) => res)
    }

    public async getAndUpdateL2TokenData(erc721L1Address: string) {
        const tokenData = this.l2Tokens[erc721L1Address] || {
            ERC721: undefined,
            CUSTOM: undefined,
        }
        this.l2Tokens[erc721L1Address] = tokenData
        const walletAddress = await this.arbTokenBridge.signer.getAddress()

        // handle custom L2 token:
        const [
            customTokenAddress,
        ] = await this.arbTokenBridge.functions.customL2Token(erc721L1Address)
        if (customTokenAddress !== ethers.constants.AddressZero) {
            const customTokenContract = ICustomToken721__factory.connect(
                customTokenAddress,
                this.arbTokenBridge.signer
            )
            tokenData.CUSTOM = {
                contract: customTokenContract,
                balance: BigNumber.from(0),
            }
            try {
                const [balance] = await customTokenContract.functions.balanceOf(
                    walletAddress
                )
                tokenData.CUSTOM.balance = balance
            } catch (err) {
                console.warn("Could not get custom token's balance", err)
            }
        }

        const l2ERC20Address = await this.getERC20L2Address(erc721L1Address)

        // check if standard arb erc20:
        if (!tokenData.ERC721) {
            if ((await this.arbTokenBridge.provider.getCode(l2ERC20Address)).length > 2) {
                const arbERC20TokenContract = await StandardArbERC721__factory.connect(
                    l2ERC20Address,
                    this.arbTokenBridge.signer
                )
                const [balance] = await arbERC20TokenContract.functions.balanceOf(
                    walletAddress
                )
                tokenData.ERC721 = {
                    contract: arbERC20TokenContract,
                    balance,
                }
            } else {
                console.info(
                    `Corresponding ArbERC20 for ${erc721L1Address} not yet deployed (would be at ${l2ERC20Address})`
                )
            }
        } else {
            const arbERC20TokenContract = await StandardArbERC721__factory.connect(
                l2ERC20Address,
                this.arbTokenBridge.signer
            )
            const [balance] = await arbERC20TokenContract.functions.balanceOf(
                walletAddress
            )
            tokenData.ERC721.balance = balance
        }

        if (tokenData.ERC721 || tokenData.CUSTOM) {
            return tokenData
        } else {
            console.warn(`No L2 token for ${erc721L1Address} found`)
            return
        }
    }

    public async getDepositTokenEventData(
        l1Transaction: providers.TransactionReceipt,
    ) {
        const factory = new EthERC721Bridge__factory()
        const contract = factory.attach(this.arbTokenBridge.address)
        const iface = contract.interface
        const event = iface.getEvent("DepositToken")
        const eventTopic = iface.getEventTopic(event)
        const logs = l1Transaction.logs.filter(log => log.topics[0] === eventTopic)
        return logs.map(
            log => (iface.parseLog(log).args as unknown) as DepositTokenEventResult
        )
    }

}

export const deployL1AndL2ERC721 = async (bridge: EigBridge, l1TestWallet: Wallet, l2TestWallet: Wallet) => {
    console.log("pre funded balance", (await l1TestWallet.getBalance()).toString());

    const customTokenFactory = await new TestCustomToken721L1__factory(l1TestWallet);
    let l1CustomToken = await customTokenFactory.deploy(
        bridge.ethTokenBridge.address
    )
    await wait(10000)

    console.log("L1 custom address", l1CustomToken.address);
    const mintRes = await l1CustomToken.mint();
    const minRec = await mintRes.wait()
    
    console.log("mint result", minRec.status)

    const bal = await l1CustomToken.balanceOf(l1TestWallet.address);
    console.log("l1 wallet balance in token", bal.toString());
    const uri = await l1CustomToken.tokenURI(0x11111111111)
    const uriRec = await mintRes.wait()
    console.log("uri ", uriRec)
    //const res = await l1CustomToken.transfer(userAddr,
    //    BigNumber.from(1)
    //);
    //let rec = await res.wait();
    const data = await bridge.getAndUpdateL1TokenData(l1CustomToken.address);
    const userBalance = data?.ERC721?.balance
    console.log("l1 wallet balance : ", userBalance?.toString())

    const customTokenFactory2 = await new TestArbCustomToken721__factory(l2TestWallet);
    console.log("deploy TestArbCustomToken");
    let arbCustomToken = await customTokenFactory2.deploy(
        bridge.arbTokenBridge.address,
        l1CustomToken.address,
        { gasLimit: 800000, gasPrice: 1 }
    )
    await wait(10000)
    console.log("deploy TestArbCustomToken after deploy");
    let rec = await arbCustomToken.deployTransaction.wait()
    if (rec.status != 1) {
        throw new Error("deployTransaction failed")
    }

    await arbCustomToken.deployed()
    console.log("L2 custom address", arbCustomToken.address, arbCustomToken.deployTransaction.hash);
    await wait(100000)
    return { l1CustomToken: l1CustomToken.address, l2CustomToken: arbCustomToken.address }
}

export const registerToken721OnL2 = async ( bridge: EigBridge, l1TestWallet: Wallet, l2TestWallet: Wallet, l1CustomTokenAddr: string, l2CustomTokenAddr: string) => {
    const l1CustomToken = TestCustomToken721L1__factory.connect(l1CustomTokenAddr, l1TestWallet);
    const arbCustomToken = TestArbCustomToken721__factory.connect(l2CustomTokenAddr, l2TestWallet);
    console.log("registerToken721OnL2 on ", arbCustomToken.address);
    const registerRes = await l1CustomToken.registerTokenOnL2(
        arbCustomToken.address,
        BigNumber.from(l1GasLimit),
        BigNumber.from(l1GasLimit),
        BigNumber.from(10),
        l1TestWallet.address,
        { gasLimit: l1GasLimit, gasPrice: 10 }
    );
    const registerRec = await registerRes.wait();
    if (registerRec.status != 1) {
        throw new Error("registerTokenOnL2 failed")
    }
    const l2txhash = await bridge.bridge.getL2TxHashByRetryableTicket(registerRec)
    console.log("getL2TxHashByRetryableTicket", l2txhash)
    const seqNum = await bridge.bridge.getInboxSeqNumFromContractTransaction(
        registerRec
    )
    if (seqNum === undefined || seqNum.length <= 0) {
        throw new Error("get seq num error")
    }
    return seqNum[0]
}

export const depositERC721 = async (bridge: EigBridge, l1TestWallet: Wallet, l2TestWallet: Wallet, l1CustomTokenAddr: string, tokenId: BigNumber) => {
    console.log("depositERC721")
    let l1CustomToken = TestCustomToken721L1__factory.connect(l1CustomTokenAddr, l1TestWallet.provider);
    const initialBridgeTokenBalance = await l1CustomToken.balanceOf(bridge.ethTokenBridge.address);
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
    const customTokenData0 = data0?.CUSTOM
    console.log("previous erc721 balance on L2", customTokenData0?.balance.toString())

    const ethERC721Bridge = EthERC721Bridge__factory.connect(
        bridge.ethTokenBridge.address,
        bridge.ethTokenBridge.signer
    )

    const tokenData = await bridge.getAndUpdateL1TokenData(l1CustomToken.address)
    if (!tokenData.ERC721) {
      throw new Error(`Can't deposit; No ERC721 at ${l1CustomToken.address}`)
    }
    const depositRes = await bridge.ethTokenBridge.functions.deposit(
        l1CustomToken.address,
        l1TestWallet.address,
        tokenId,
        BigNumber.from(maxGas),
        BigNumber.from(maxGas),
        BigNumber.from(1),
        "0x",
        { gasLimit: 594949, gasPrice: l1GasPrice }
    )
    const depositRec = await depositRes.wait();

    if (depositRec.status != 1) {
        throw new Error("despoit failed")
    }

    const finalBridgeTokenBalance = await l1CustomToken.balanceOf(
        bridge.ethTokenBridge.address
    )
    console.log("finalBridgeTokenBalance", finalBridgeTokenBalance.toString())

    if (initialBridgeTokenBalance.add(1).eq(finalBridgeTokenBalance)) {
        console.log("deposit done");
    } else {
        console.log(
            "deposit failed",
            initialBridgeTokenBalance.toString(),
            tokenId.toString(),
            finalBridgeTokenBalance.toString()
        )
    }

    const tokenDepositData = (
        await bridge.getDepositTokenEventData(depositRec)
    )[0] as DepositTokenEventResult
    console.log("token deposit data", tokenDepositData)
    const seqNum = tokenDepositData.seqNum
    const retryableReceipt = await bridge.bridge.waitForRetriableReceipt(
        seqNum)
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
                    tokenId.toString())

                    const offset = customTokenData?.balance.sub(initCustomTokenData?.balance || 0);
                    console.log("eq", offset?.toString(), tokenId.toString())
                    if (!offset?.eq(tokenId)) {
                        // TODO
                        //throw new Error("Invalid balance")
                    }
}

export const approveToken721 = async (
    bridge: EigBridge,
    l1TestWallet: Wallet,
    l2TestWallet: Wallet,
    erc721L1Address: string,
    tokenId: BigNumber,
) => {
    const erc721Token = await ERC721__factory.connect(erc721L1Address, l1TestWallet);
    console.log("Approve")
    return erc721Token.functions.approve(
        bridge.ethTokenBridge.address,
        tokenId,
        {}
    )
}

export const withdrawERC721 = async (
    bridge: EigBridge,
    l1TestWallet: Wallet,
    l2TestWallet: Wallet,
    l1CustomTokenAddr: string, arbCustomTokenAddr: string, tokenId : BigNumber) => {
        console.log("Withdraw")
        const l2CustomToken = TestArbCustomToken721__factory.connect(arbCustomTokenAddr, l2TestWallet)

        const initialBridgeTokenBalance = await l2CustomToken.balanceOf(l2TestWallet.address);
        console.log("balance in l2 token", initialBridgeTokenBalance?.toString());

        const l1CustomToken = TestCustomToken721L1__factory.connect(l1CustomTokenAddr, l1TestWallet.provider);
        const initialBridgeTokenBalanceL1 = await l1CustomToken.balanceOf(bridge.ethTokenBridge.address);
        console.log("balance in l1 token", initialBridgeTokenBalanceL1.toString());

        const withdrawRes = await l2CustomToken.withdraw(
            l1TestWallet.address,
            tokenId,
            { gasLimit: maxGas, gasPrice: 1 }
        )
        const withdrawRec = await withdrawRes.wait()
        console.log("withdraw done")
        const withdrawEventData = (
            await bridge.bridge.getWithdrawalsInL2Transaction(withdrawRec)
        )[0]
        console.log("withdraw data", withdrawEventData)

        const txHash = withdrawRec.transactionHash
        console.log("withdraw hash:", txHash)
        const initiatingTxnReceipt = await bridge.arbTokenBridge.provider.getTransactionReceipt(txHash);
        const outGoingMessagesFromTxn = await bridge.bridge.getWithdrawalsInL2Transaction(initiatingTxnReceipt)
        console.log(outGoingMessagesFromTxn)
        const { batchNumber, indexInBatch } = outGoingMessagesFromTxn[0]
        if (!batchNumber.eq(withdrawEventData.batchNumber) ||
            !indexInBatch.eq(withdrawEventData.indexInBatch)) {
            console.log("Invalid batchNumber or indexInBatch")
        process.exit(-1)
        }

        console.log("from outgoing msg", outGoingMessagesFromTxn[0])
        const outgoingMessageState = await bridge.bridge.getOutGoingMessageState(
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

        let receipt
        while (receipt === undefined) {
            try {
                receipt = await bridge.bridge.triggerL2ToL1Transaction(
                    batchNumber,
                    indexInBatch
                )
            } catch (error) {
                console.log(error)
                receipt = undefined
            }
            await wait(100000);
        }
        if (receipt.status != 1) {
            console.log("trigger failed")
            process.exit(-1)
        }

        const curBridgeTokenBalance = await l2CustomToken.balanceOf(l2TestWallet.address);
        console.log("balance in l2 token", curBridgeTokenBalance?.toString());
        const offset = initialBridgeTokenBalance?.sub(curBridgeTokenBalance || 0);
        console.log("eq ", offset?.toString())
        if (!offset.eq(tokenId)) {
            console.log("invalid withdraw")
            process.exit(-1);
        }
        const curTokenBalanceL1 = await l1CustomToken.balanceOf(bridge.ethTokenBridge.address);
        console.log("balance in l1 token", curTokenBalanceL1.toString());
        const offset2 = curTokenBalanceL1?.sub(initialBridgeTokenBalanceL1 || 0);
        console.log("eq", offset2?.toString(), tokenId.toString())
    }

    export const getWalletBalance = async (
        bridge: EigBridge,
        l1TestWallet: Wallet,
        l2TestWallet: Wallet,
    ) => {
        const testWalletL1EthBalance = await bridge.ethTokenBridge.signer.getBalance()
        const testWalletL2EthBalance = await bridge.arbTokenBridge.signer.getBalance()
        console.log(testWalletL1EthBalance.toString(), testWalletL2EthBalance.toString())
        return [testWalletL1EthBalance, testWalletL2EthBalance]
    }

    export const depositETH721 = async(
        bridge: EigBridge,
        l1TestWallet: Wallet,
        l2TestWallet: Wallet,
        ethToL2DepositAmount: BigNumber
    ) => {
            const res2 = await bridge.bridge.depositETH(ethToL2DepositAmount, l1TestWallet.address)
            const rec2 = await res2.wait();
            //console.log(rec2) 
            if (rec2.status != 1) {
                throw new Error("Deposit l1 wallet error")
            }

            let bridgeEthBalance = await l2TestWallet.provider.getBalance(deployments.ethERC721Bridge)
            console.log("deployments.ethERC20Bridge balance: ", bridgeEthBalance.toString()) 

            if (bridgeEthBalance.gt(BigNumber.from(0))) {
                console.log("Skip deposit ethERC20Bridge")
            }

            const res = await bridge.bridge.depositETH(ethToL2DepositAmount, deployments.ethERC721Bridge)	
            const rec = await res.wait();
            //console.log(rec) 
            if (rec.status != 1) {
                throw new Error("Deposit error")
            }
            await wait(10000)
            let balance = await getWalletBalance(bridge, l1TestWallet, l2TestWallet) 
            console.log(balance[0].toString(), balance[1].toString())

            let bridgeEthBalance2 = await l2TestWallet.provider.getBalance(deployments.ethERC721Bridge)
            console.log("after deployments.ethERC20Bridge balance: ", bridgeEthBalance2.toString()) 
        }
