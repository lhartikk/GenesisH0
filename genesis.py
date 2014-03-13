import hashlib
import binascii
import struct
import array
import struct
import time
import os
import sys
import optparse
import scrypt

from construct import *

parser = optparse.OptionParser()
parser.add_option("-t", "--time", dest="time", default=int(time.time()), 
                 type="int", help="the (unix) time when the genesisblock is created")
parser.add_option("-z", "--timestamp", dest="timestamp", default="The Times 03/Jan/2009 Chancellor on brink of second bailout for banks",
                 type="string", help="the pszTimestamp found in the coinbase of the genesisblock")
parser.add_option("-n", "--nonce", dest="nonce", default=0,
                 type="int", help="the first value of the nonce that will be incremented when searching the genesis hash")
parser.add_option("-s", "--scrypt", dest="scrypt", default=False, action="store_true",
                  help="calculate genesis block using scrypt")
parser.add_option("-p", "--pubkey", dest="pubkey", default="04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f",
                 type="string", help="The pubkey found in the output script")


(options, args) = parser.parse_args()

pszTimestamp = options.timestamp
startNonce = options.nonce
nTime = options.time
isScrypt = options.scrypt
outputScriptPubKey = options.pubkey

bits = 0x1d00ffff
target = 0x00ffff * 2**(8*(0x1d - 3)) 

if isScrypt:
  print 'algorithm: scrypt'
  bits = 0x1e0ffff0
  target = 0x0ffff0 * 2**(8*(0x1e - 3))
else:
  print 'algorithm: sha256'



scriptPrefix = '04ffff001d0104' + chr(len(pszTimestamp)).encode('hex')
scriptSig = (scriptPrefix + pszTimestamp.encode('hex')).decode('hex')
scriptPubKeyLen = '41'
OP_CHECKSIG = 'ac'

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

print "merkle hash: " + hash[::-1].encode('hex_codec')
print "pszTimestamp: " + pszTimestamp
print "pubkey: " + outputScriptPubKey
print "time: " + str(nTime)
print "bits: " + str(hex(bits))

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

if not(isScrypt):
  while True:
    if nonce % interval == interval - 1:
      now = time.time()
      hashrate = round(interval/(now - millis))
      genTime = round(pow(2, 32) / hashrate / 3600, 1)
      sys.stdout.write('\r' + str(hashrate) + " hash/s, estimate: " + str(genTime) + "h")
      sys.stdout.flush()
      millis = now

    genesisHash = hashlib.sha256(hashlib.sha256(dataBlock).digest()).digest()

    if int(genesisHash[::-1].encode('hex_codec'), 16) < target:
      print ''
      print 'genesis hash found!'
      print 'nonce: ' + str(nonce)
      print 'genesis hash: '+ genesisHash[::-1].encode('hex_codec')
      break
    else:
     nonce = nonce + 1
     dataBlock = dataBlock[0:len(dataBlock) - 4] + struct.pack('<I', nonce)
else:
  interval = 1000
  while True:
    if nonce % interval == interval - 1:
      now = time.time()
      hashrate = round(interval/(now - millis))
      genTime =  round(0.00024414 * pow(2, 32) / hashrate / 3600, 1)
      sys.stdout.write('\r' + str(hashrate) + " hash/s, estimate: " + str(genTime) + "h")
      sys.stdout.flush()
      millis = now

    scryptHash = scrypt.hash(dataBlock,dataBlock,1024,1,1,32)

    if int(scryptHash[::-1].encode('hex_codec'), 16) < target:

      genesisHash = hashlib.sha256(hashlib.sha256(dataBlock).digest()).digest()
      print ''
      print 'genesis hash found!'
      print 'nonce: ' + str(nonce)
      print 'genesis hash: '+ genesisHash[::-1].encode('hex_codec')
      break
    else:
     nonce = nonce + 1
     dataBlock = dataBlock[0:len(dataBlock) - 4] + struct.pack('<I', nonce)

