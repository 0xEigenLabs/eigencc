import { BigNumber, Wallet, providers, constants, utils } from 'ethers'
import { Bridge, DepositTokenEventResult, OutgoingMessageState } from 'arb-ts'
import { PayableOverrides } from '@ethersproject/contracts'

const { eigenLog, requireEnvVariables } = require('arb-shared-dependencies')
const deployments = require('../deployment.json')

import { TestCustomToken721L1 } from '../typechain/TestCustomToken721L1'
import { TestArbCustomToken721 } from '../typechain/TestArbCustomToken721'
import { TestCustomToken721L1__factory } from '../typechain/factories/TestCustomToken721L1__factory'
import { TestArbCustomToken721__factory } from '../typechain/factories/TestArbCustomToken721__factory'

const MIN_APPROVAL = constants.MaxUint256

require('dotenv').config()
requireEnvVariables(['DEVNET_PRIVKEY', 'L2RPC', 'L1RPC'])

import {
  wait,
  approveToken721,
  depositETH721,
  depositERC721,
  withdrawERC721,
  deployL1AndL2ERC721,
  registerToken721OnL2,
  EigBridge,
} from './common_erc721'

const ethProvider = new providers.JsonRpcProvider(process.env.L1RPC)
const arbProvider = new providers.JsonRpcProvider(process.env.L2RPC)
const testSk = process.env.DEVNET_PRIVKEY || ''
const l1TestWallet = new Wallet(testSk, ethProvider)
const l2TestWallet = new Wallet(testSk, arbProvider)
const userAddr = '0xD73EbFad38707CB2AB4D127A43A193Bc526F5151'

const bridge = new EigBridge(
  deployments.ethERC721Bridge,
  deployments.arbToken721Bridge,
  l1TestWallet,
  l2TestWallet
)

const main = async () => {
  await depositETH721(
    bridge,
    l1TestWallet,
    l2TestWallet,
    utils.parseEther('1.0')
  )
  console.log('depositETH721 done')
  let tokenPair = await deployL1AndL2ERC721(bridge, l1TestWallet, l2TestWallet)
  console.log(tokenPair)
  let seqNum = await registerToken721OnL2(
    bridge,
    l1TestWallet,
    l2TestWallet,
    tokenPair.l1CustomToken,
    tokenPair.l2CustomToken
  )
  console.log('seqNum', seqNum)
  const registerRec = await bridge.bridge.waitForRetriableReceipt(seqNum)
  if (registerRec.status != 1) {
    throw Error('Invalid recepit')
  }

  //FIXME: tokenId may be overflow
  let tokenId = BigNumber.from(0x11111111111)
  // mint on L1
  //TODO

  await wait(15000)
  await approveToken721(
    bridge,
    l1TestWallet,
    l2TestWallet,
    tokenPair.l1CustomToken,
    tokenId
  )
  console.log('Approve done')
  const l2CustomToken = TestArbCustomToken721__factory.connect(
    tokenPair.l2CustomToken,
    l2TestWallet
  )
  console.log('connect done')
  await depositERC721(
    bridge,
    l1TestWallet,
    l2TestWallet,
    tokenPair.l1CustomToken,
    tokenId
  )
  console.log('deposit done')
  await withdrawERC721(
    bridge,
    l1TestWallet,
    l2TestWallet,
    tokenPair.l1CustomToken,
    tokenPair.l2CustomToken,
    tokenId
  )
}

main()
  .then(() => process.exit(0))
  .catch(error => {
    console.error(error)
    process.exit(1)
  })
