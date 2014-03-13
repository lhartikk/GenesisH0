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


def main():
  options = getArgs()
  pszTimestamp = options.timestamp
  startNonce = options.nonce
  nTime = options.time
  isScrypt = options.scrypt
  pubkey = options.pubkey


  #see https://en.bitcoin.it/wiki/Difficulty for the magic numbers
  bits = 0x1d00ffff
  target = 0x00ffff * 2**(8*(0x1d - 3)) 

  if isScrypt:
    print 'algorithm: scrypt'
    bits = 0x1e0ffff0
    target = 0x0ffff0 * 2**(8*(0x1e - 3))
  else:
    print 'algorithm: sha256'

  inputScript = createInputScript(pszTimestamp)
  outputScript = createOutputScript(pubkey)
  tx = createTransaction(inputScript, outputScript)

  #hash merkle root is the double sha256 hash of the transaction(s) 
  hashMerkleRoot = hashlib.sha256(hashlib.sha256(tx).digest()).digest()

  print "merkle hash: " + hashMerkleRoot[::-1].encode('hex_codec')
  print "pszTimestamp: " + pszTimestamp
  print "pubkey: " + pubkey
  print "time: " + str(nTime)
  print "bits: " + str(hex(bits))

  dataBlock = createBlockHeader(hashMerkleRoot, nTime, bits, startNonce)

  print 'Searching for genesis hash..'
  genesisHash, nonce = generateHash(dataBlock, isScrypt, startNonce, target)
  print "genesis hash found!"
  print "nonce: " + str(nonce)
  print "genesis hash: " + genesisHash.encode('hex_codec')

def getArgs():
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
  return options



def createInputScript(pszTimestamp):
  scriptPrefix = '04ffff001d0104' + chr(len(pszTimestamp)).encode('hex')
  return (scriptPrefix + pszTimestamp.encode('hex')).decode('hex')

def createOutputScript(pubkey):
  scriptLen = '41'
  OP_CHECKSIG = 'ac'
  return (scriptLen + pubkey + OP_CHECKSIG).decode('hex')

def createTransaction(inputScript, outputScript):
  transaction = Struct("transaction",
    Bytes("version", 4),
    Byte("numInputs"),
    StaticField("prevOutput", 32),
    UBInt32('prevoutIndex'),
    Byte('scriptSigLen'),
    Bytes('scriptSig', len(inputScript)),
    UBInt32('sequence'),
    Byte('numOutputs'),
    Bytes('outValue', 8),
    Byte('outputScriptLen'),
    Bytes('outputScript',  0x43),
    UBInt32('locktime'))

  tx = transaction.parse('\x00'*(127 + len(inputScript)))

  tx.version = struct.pack('<I', 1)
  tx.numInputs = 1
  tx.prevOutput = struct.pack('<qqqq', 0,0,0,0)
  tx.prevoutIndex = 0xFFFFFFFF
  tx.scriptSigLen = len(inputScript)
  tx.scriptSig = inputScript
  tx.sequence = 0xFFFFFFFF
  tx.numOutputs = 1
  tx.outValue = struct.pack('<q' ,0x000000012a05f200) #50 coins
  tx.outputScriptLen = 0x43
  tx.outputScript = outputScript
  tx.locktime = 0 

  return transaction.build(tx)


def createBlockHeader(hashMerkleRoot, time, bits, nonce):
  blockHeader = Struct("blockHeader",
    Bytes("version",4),
    Bytes("hashPrevBlock", 32),
    Bytes("hashMerkleRoot", 32),
    Bytes("Time", 4),
    Bytes("Bits", 4),
    Bytes("Nonce", 4))

  genesisblock = blockHeader.parse('\x00'*80)
  genesisblock.version = struct.pack('<I', 1)
  genesisblock.hashPrevBlock = struct.pack('<qqqq', 0,0,0,0)
  genesisblock.hashMerkleRoot = hashMerkleRoot
  genesisblock.Time = struct.pack('<I', time)
  genesisblock.Bits =  struct.pack('<I', bits)
  genesisblock.Nonce = struct.pack('<I', nonce)
  return blockHeader.build(genesisblock)

def generateHash(dataBlock, isScrypt, startNonce, target):
  nonce = startNonce
  millis = time.time()
  difficulty = float(0xFFFF) * 2**208 / target
  hashRateInterval = 2000000 * difficulty
  while True:
    if nonce % hashRateInterval == hashRateInterval - 1:
      now = time.time()
      hashrate = round(hashRateInterval/(now - millis))
      genTime = round(difficulty * pow(2, 32) / hashrate / 3600, 1)
      sys.stdout.write('\r' + str(hashrate) + " hash/s, estimate: " + str(genTime) + "h")
      sys.stdout.flush()
      millis = now
    shaHash = hashlib.sha256(hashlib.sha256(dataBlock).digest()).digest()[::-1]

    if isScrypt:
      headerHash = scrypt.hash(dataBlock,dataBlock,1024,1,1,32)[::-1]
    else:
      headerHash = shaHash

    if int(headerHash.encode('hex_codec'), 16) < target:
      return (shaHash, nonce)
    else:
     nonce = nonce + 1
     dataBlock = dataBlock[0:len(dataBlock) - 4] + struct.pack('<I', nonce)  

main()