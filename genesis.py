import hashlib
import binascii
import struct
import array

from construct import *


OP_CHECKSIG = 'ac'
scriptSig = '04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73'.decode('hex')
scriptPubKeyLen = '41'
outputScriptPubKey = '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f'
outputScript = (scriptPubKeyLen + outputScriptPubKey + OP_CHECKSIG).decode('hex')
startNonce = 0x1DAC2B7C

version = '01000000'.decode('hex')
numInputs = 1
numOutputs = 1
locktime = 0
prevOutput =  '\x00' * 32
prevoutIndex = 0xFFFFFFFF
sequence = 0xFFFFFFFF
outValue = '00f2052a01000000'.decode('hex')
scriptSigLen = 0x4D
outputScriptLen = 0x43

transaction = Struct("transaction",
Bytes("version", 4),
Byte("numInputs"),
StaticField("prevOutput", 32),
UBInt32('prevoutIndex'),
Byte('scriptSigLen'),
Bytes('scriptSig', scriptSigLen),
UBInt32('sequence'),
Byte('numOutputs'),
Bytes('outValue', 8),
Byte('outputScriptLen'),
Bytes('outputScript',  outputScriptLen),
UBInt32('locktime'))

tx = transaction.parse('\x00'*204)
tx.version = version
tx.numInputs = numInputs
tx.prevOutput = prevOutput
tx.prevoutIndex = prevoutIndex
tx.scriptSigLen = scriptSigLen
tx.scriptSig = scriptSig
tx.sequence = sequence
tx.numOutputs = numOutputs
tx.outValue = outValue
tx.outputScriptLen = outputScriptLen
tx.outputScript = outputScript
tx.locktime = locktime

print "tx"
print transaction.build(tx).encode('hex_codec')
print "txover"

hash = hashlib.sha256(hashlib.sha256(transaction.build(tx)).digest()).digest()
hashMerkleRoot =hash.encode('hex_codec')
hashPrevBlock = '\x00' * 32
time = '29AB5F49'.decode('hex')
bits = 'FFFF001D'.decode('hex')
nonce = hex(startNonce)[2:].decode('hex')



#chunks, chunk_size = len(hashMerkleRoot), 2
#littleEndian = ''.join([ hashMerkleRoot[i:i+chunk_size] for i in range(0, chunks, chunk_size) ][::-1])


print "merkle hash: " + hashMerkleRoot
print "time: " + str(int(time.encode('hex_codec'), 16))
print "bits: " + bits.encode('hex_codec')



blockHeader = Struct("blockHeader",
  Bytes("version",4),
  Bytes("hashPrevBlock", 32),
  Bytes("hashMerkleRoot", 32),
  Bytes("Time", 4),
  Bytes("Bits", 4),
  Bytes("Nonce", 4))


genesisblock = blockHeader.parse('\x00'*80)
genesisblock.version = version
genesisblock.hashPrevBlock = hashPrevBlock
genesisblock.hashMerkleRoot = hashMerkleRoot.decode('hex')
genesisblock.Time = time
genesisblock.Bits = bits
genesisblock.Nonce = nonce

print "block:"
print blockHeader.build(genesisblock).encode('hex_codec')

i = 0

while True:
  genesisHash = hashlib.sha256(hashlib.sha256(blockHeader.build(genesisblock)).digest()).digest()
  blockHash = blockHeader.build(genesisblock)

  if True or int(genesisHash.encode('hex_codec')[60:64], 16) == 0:
    print 'genesis hash found!'
    print 'genesis hash: '+ genesisHash.encode('hex_codec')
    break
  else:
    i = i + 1
    nonce = nonce = hex(startNonce + i)[2:].decode('hex')
    genesisblock.Nonce = nonce