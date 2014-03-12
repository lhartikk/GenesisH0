import hashlib
import binascii
import struct
import array
import struct
import time
import os
import sys

from construct import *


def changeEndian(stringHex):
  chunks, chunk_size = len(stringHex), 2
  return ''.join([ stringHex[i:i+chunk_size] for i in range(0, chunks, chunk_size) ][::-1])

OP_CHECKSIG = 'ac'
pszTimestamp = 'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks'
scriptPrefix = '04ffff001d'
scriptSig = ('04ffff001d010445' + pszTimestamp.encode('hex')).decode('hex')
scriptPubKeyLen = '41'
outputScriptPubKey = '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f'
outputScript = (scriptPubKeyLen + outputScriptPubKey + OP_CHECKSIG).decode('hex')

startNonce = 2083236897
nTime = 1231006505
bits = 0x1d00ffff

version = 1
numInputs = 1
numOutputs = 1
locktime = 0
prevOutput =  struct.pack('<qqqq', 0,0,0,0)
prevoutIndex = 0xFFFFFFFF
sequence = 0xFFFFFFFF
outValue = 0x000000012a05f200 
scriptSigLen = len(scriptSig)
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

tx = transaction.parse('\x00'*(127 + scriptSigLen))
tx.version = struct.pack('<I', version)
tx.numInputs = numInputs
tx.prevOutput = prevOutput
tx.prevoutIndex = prevoutIndex
tx.scriptSigLen = scriptSigLen
tx.scriptSig = scriptSig
tx.sequence = sequence
tx.numOutputs = numOutputs
tx.outValue = struct.pack('<q' ,outValue)
tx.outputScriptLen = outputScriptLen
tx.outputScript = outputScript
tx.locktime = locktime

hash = hashlib.sha256(hashlib.sha256(transaction.build(tx)).digest()).digest()
hashMerkleRoot =hash.encode('hex_codec')
hashPrevBlock = struct.pack('<qqqq', 0,0,0,0)

print "merkle hash: " + hashMerkleRoot
print "time: " + str(nTime)
print "bits: " + str(bits)
print "pszTimestamp: " + pszTimestamp



blockHeader = Struct("blockHeader",
  Bytes("version",4),
  Bytes("hashPrevBlock", 32),
  Bytes("hashMerkleRoot", 32),
  Bytes("Time", 4),
  Bytes("Bits", 4),
  Bytes("Nonce", 4))


genesisblock = blockHeader.parse('\x00'*80)
genesisblock.version = struct.pack('<I', version)
genesisblock.hashPrevBlock = hashPrevBlock
genesisblock.hashMerkleRoot = hashMerkleRoot.decode('hex')
genesisblock.Time = struct.pack('<I', nTime)
genesisblock.Bits = struct.pack('<I', bits)
genesisblock.Nonce = struct.pack('<I', startNonce)

nonce = startNonce
millis = time.time()
interval = 5000000
print 'Searching for genesis hash..'
dataBlock = blockHeader.build(genesisblock)
while True:

  if nonce % interval == 0:
    now = time.time()
    sys.stdout.write('\r' + str(round(interval/(now - millis)/1000)) + " khash/s")
    sys.stdout.flush()
    millis = now
  genesisHash = hashlib.sha256(hashlib.sha256(dataBlock).digest()).digest()

  '''if int(genesisHash.encode('hex_codec')[56:64], 16) == 0:
    print 'genesis hash found!'
    print 'nonce: ' + str(nonce)
    print 'genesis hash: '+ genesisHash.encode('hex_codec')
    print 'genesis hash: '+ changeEndian(genesisHash.encode('hex_codec'))
    break
  else:'''
  nonce = nonce + 1
  dataBlock = dataBlock[0:66] + struct.pack('<I', nonce)


