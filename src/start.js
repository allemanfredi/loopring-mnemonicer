const { HDNode } = require('@ethersproject/hdnode')
const { hashPersonalMessage, ecsign, isValidSignature, toRpcSig, toBuffer, sha256 } = require('ethereumjs-util')
const { EdDSA } = require('./lib/eddsa')

const start = ({ mnemonic, index, LoopringExchangeContractAddress, keyNonce }) => {
  const hdwallet = HDNode.fromMnemonic(mnemonic)
  const { address, privateKey: ethPrivateKey } = hdwallet.derivePath(`m/44'/60'/0'/0/${parseInt(index, 10)}`)

  // prettier-ignore
  const message = `Sign this message to access Loopring Exchange: ${LoopringExchangeContractAddress} with key nonce: ${keyNonce}`
  const { v, r, s } = ecsign(hashPersonalMessage(Buffer.from(message)), toBuffer(ethPrivateKey))

  if (!isValidSignature(v, r, s)) {
    throw new Error('Invalid signature generated for getting Loopring key pair')
  }

  const entropy = sha256(toBuffer(toRpcSig(v, r, s)))

  const { publicKeyX, publicKeyY, secretKey } = EdDSA.getKeyPair(entropy)

  console.log('loopringPrivateKey:', secretKey)
  console.log('loopringPublicKeyX:', publicKeyX)
  console.log('loopringPublicKeyY:', publicKeyY)
  console.log('ethPrivateKey:', ethPrivateKey)
  console.log('address:', address)
}

module.exports = start
