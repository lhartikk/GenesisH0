import hashlib
import binascii
import struct
import array
import struct
import time
import os
import sys
import optparse

from construct import *


def changeEndian(stringHex):
  chunks, chunk_size = len(stringHex), 2
  return ''.join([ stringHex[i:i+chunk_size] for i in range(0, chunks, chunk_size) ][::-1])


parser = optparse.OptionParser()
parser.add_option("-t", "--time", dest="time", default=int(time.time()), 
                 type="int", help="the (unix) time when the genesisblock is created")
parser.add_option("-z", "--timestamp", dest="timestamp", default="The Times 03/Jan/2009 Chancellor on brink of second bailout for banks",
                 type="string", help="the pszTimestamp found in the coinbase of the genesisblock")
parser.add_option("-n", "--nonce", dest="nonce", default=0,
                 type="int", help="the first value of the nonce that will be incremented when searching the genesis hash")
parser.add_option("-s", "--scrypt", dest="scrypt", default=False, action="store_true",
                  help="calculate genesis block using scrypt")

(options, args) = parser.parse_args()

pszTimestamp = options.timestamp
startNonce = options.nonce
nTime = options.time
isScrypt = options.scrypt

if isScrypt:
  print 'algorithm: scrypt'
else:
  print 'algorithm: sha256'



bits = 0x1d00ffff

scriptPrefix = '04ffff001d0104' + chr(len(pszTimestamp)).encode('hex')
scriptSig = (scriptPrefix + pszTimestamp.encode('hex')).decode('hex')
scriptPubKeyLen = '41'
OP_CHECKSIG = 'ac'
outputScriptPubKey = '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f'
outputScript = (scriptPubKeyLen + outputScriptPubKey + OP_CHECKSIG).decode('hex')

version = 1
numInputs = 1
numOutputs = 1
locktime = 0
prevOutput =  struct.pack('<qqqq', 0,0,0,0)
prevoutIndex = 0xFFFFFFFF
sequence = 0xFFFFFFFF
outValue = 0x000000012a05f200 #50 coins
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
print "bits: " + str(hex(bits))
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
genesisblock.Bits =  struct.pack('<I', bits)
genesisblock.Nonce = struct.pack('<I', startNonce)

nonce = startNonce
millis = time.time()
interval = 2000000
print 'Searching for genesis hash..'
dataBlock = blockHeader.build(genesisblock)
while True:

  if nonce % interval == interval - 1:
    now = time.time()
    hashrate = round(interval/(now - millis)/1000)
    genTime = round(pow(2, 32) / hashrate / 1000 / 3600, 1)
    sys.stdout.write('\r' + str(hashrate) + " khash/s, estimate: " + str(genTime) + "h")
    sys.stdout.flush()
    millis = now
  genesisHash = hashlib.sha256(hashlib.sha256(dataBlock).digest()).digest()

  if int(genesisHash.encode('hex_codec')[56:64], 16) == 0:
    print ''
    print 'genesis hash found!'
    print 'nonce: ' + str(nonce)
    print 'genesis hash: '+ changeEndian(genesisHash.encode('hex_codec'))
    break
  else:
   nonce = nonce + 1
   dataBlock = dataBlock[0:66] + struct.pack('<I', nonce)


