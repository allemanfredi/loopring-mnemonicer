const { version } = require('./package.json')
const start = require('./src/start')

const { argv } = require('yargs')
  .version(version)
  .usage('Usage: $0 [options]')
  .option('mnemonic', {
    type: 'string',
    alias: 'm',
    describe: 'Ethereum mnemonic passphrase',
    nargs: 1
  })
  .option('index', {
    type: 'string',
    alias: 'i',
    describe: 'Ethereum mnemonic index',
    nargs: 1
  })
  .option('keyNonce', {
    type: 'string',
    alias: 'k',
    describe: 'Loopring account key nonce',
    nargs: 1
  })
  .strict()
  .help('h')
  .alias('h', 'help')

const { mnemonic, index, keyNonce } = argv

const params = {
  mnemonic,
  index: index || 0,
  keyNonce: keyNonce || 0,
  LoopringExchangeContractAddress: '0x0BABA1Ad5bE3a5C0a66E7ac838a129Bf948f1eA4'
}

start(params)
