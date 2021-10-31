require('dotenv').config()
module.exports = {
  solidity: '0.6.11',
  networks: {
    l1: {
      url: process.env['L1RPC'] || '',
      accounts: [process.env['DEVNET_PRIVKEY']],
    },
    l2: {
      gasPrice: 0,
      url: process.env['L2RPC'] || '',
      accounts: [process.env['DEVNET_PRIVKEY']],
    },
  },
}
