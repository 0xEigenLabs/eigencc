const hardhatConfig = require('./hardhat.config.js')
require('dotenv').config()

const wait = (ms = 0) => {
  return new Promise(res => setTimeout(res, ms || 0))
}

const eigenLog = async text => {
  console.log('Eigen Demo:', text)
  await wait(2000)

  console.log('Lets')
  await wait(1000)

  console.log('Go ➡️')
  await wait(1000)
  console.log('...🚀')
  await wait(1000)
  console.log('')
}

const requireEnvVariables = envVars => {
  for (const envVar of envVars) {
    if (!process.env[envVar]) {
      throw new Error(`Error: set your '${envVar}' environmental variable `)
    }
  }
  console.log('Environmental variables properly set 👍')
}
module.exports = {
  eigenLog,
  hardhatConfig,
  requireEnvVariables,
}
