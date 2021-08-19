const { providers, Wallet } = require('ethers')
const { Bridge, OutgoingMessageState } = require('arb-ts')
const { requireEnvVariables } = require('arb-shared-dependencies')

require('dotenv').config()
requireEnvVariables(['DEVNET_PRIVKEY', 'L2RPC', 'L1RPC', 'ERC20_BRIDGE', 'L2_TOKEN_BRIDGE'])

const wait = (ms = 0) => {
  return new Promise(res => setTimeout(res, ms || 10000))
}

/**
 * Set up: instantiate L1 / L2 wallets connected to providers
 */

const walletPrivateKey = process.env.DEVNET_PRIVKEY

const l1Provider = new providers.JsonRpcProvider(process.env.L1RPC)
const l2Provider = new providers.JsonRpcProvider(process.env.L2RPC)

const l1Wallet = new Wallet(walletPrivateKey, l1Provider)
const l2Wallet = new Wallet(walletPrivateKey, l2Provider)

module.exports = async txnHash => {
  /**
   / * We start with a txn hash; we assume this is transaction that triggered an L2 to L1 Message on L2 (i.e., ArbSys.sendTxToL1)
   */

  if (!txnHash)
    throw new Error(
      'Provide a transaction hash of an L2 transaction that sends an L2 to L1 message'
    )
  if (!txnHash.startsWith('0x') || txnHash.trim().length != 66)
    throw new Error(`Hmm, ${txnHash} doesn't look like a txn hash...`)
  /**
   * Use wallets to create an arb-ts bridge instance
   * We'll use bridge for its convenience methods around outbox-execution
   */
  let erc20Bridge = process.env.ERC20_BRIDGE
  let arbTokenBridge = process.env.L2_TOKEN_BRIDGE

  console.log("ENV", process.env)

  const bridge = new Bridge(erc20Bridge, arbTokenBridge, l1Wallet, l2Wallet)

  /**
   * First, let's find the Arbitrum txn from the txn hash provided
   */
  const initiatingTxnReceipt = await bridge.l2Provider.getTransactionReceipt(
    txnHash
  )

  if (!initiatingTxnReceipt)
    throw new Error(
      `No Arbitrum transaction found with provided txn hash: ${txnHash}`
    )

  /**
   * In order to trigger the outbox message, we'll first need the outgoing messages batch number and index; together these two things uniquely identify an outgoing message.
   * To get this data, we'll use getWithdrawalsInL2Transaction, which retrieves this data from the L2 events logs
   */

  const outGoingMessagesFromTxn = await bridge.getWithdrawalsInL2Transaction(
    initiatingTxnReceipt
  )

  if (outGoingMessagesFromTxn.length === 0)
    throw new Error(`Txn ${txnHash} did not initiate an outgoing messages`)

  /**
   * Note that in principle, a single transaction could trigger any number of outgoing messages; the common case will be there's only one.
   * For the sake of this script, we assume there's only one / just grad the first one.
   */
  const { batchNumber, indexInBatch } = outGoingMessagesFromTxn[0]

  /**
   * We've got batchNumber and IndexInBatch in hand; but before we try to execute out message, we need to make sure it's confirmed! (It can only be confirmed after the dispute period; Arbitrum is an optimistic rollup after-all)
   * Here we'll do a period check; once getOutgoingMessageState tells us our txn is confirm, we'll move on to execution
   */
  const outgoingMessageState = await bridge.getOutGoingMessageState(
    batchNumber,
    indexInBatch
  )
  console.log(
    `Waiting for message to be confirmed: Batchnumber: ${batchNumber}, IndexInBatch ${indexInBatch}`
  )

  while (!outgoingMessageState === OutgoingMessageState.CONFIRMED) {
    await wait(1000 * 60)
    const outgoingMessageState = await bridge.getOutGoingMessageState(
      batchNumber,
      indexInBatch
    )

    switch (outgoingMessageState) {
      case OutgoingMessageState.NOT_FOUND: {
        console.log('Message not found; something strange and bad happened')
        process.exit(1)
        break
      }
      case OutgoingMessageState.EXECUTED: {
        console.log(`Message already executed! Nothing else to do here`)
        process.exit(1)
        break
      }
      case OutgoingMessageState.UNCONFIRMED: {
        console.log(`Message not yet confirmed; we'll wait a bit and try again`)
        break
      }

      default:
        break
    }
  }

  console.log('Transaction confirmed! Trying to execute now')
  /**
   * Now that its confirmed, we can retrieve the Merkle proof data from the chain, and execute our message in its outbox entry.
   * triggerL2ToL1Transaction handles these steps
   */
  const res = await bridge.triggerL2ToL1Transaction(batchNumber, indexInBatch)
    // check  res.status == 1

  console.log('Done! Your transaction is executed', res)
}
