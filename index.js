
var sodium = require('chloride')
var scalarmult = sodium.crypto_scalarmult
var box  = sodium.crypto_box_easy
var secretbox = sodium.crypto_secretbox_easy
var secretbox_open = sodium.crypto_secretbox_open_easy
var keypair = sodium.crypto_box_keypair
var concat = Buffer.concat

function randombytes(n) {
  var b = new Buffer(n)
  sodium.randombytes(b)
  return b
}

function setMax (m) {
  m = m || DEFAULT_MAX
  if (m < 1 || m > 255)
    throw new Error('max recipients must be between 0 and 255.')
  return m
}


const DEFAULT_MAX = 7

exports.encrypt =
exports.multibox = function (msg, recipients, symkeys, max) {

  if(!Array.isArray(symkeys))
    max = symkeys, symkeys = []

  max = setMax(max)
  var nonce = randombytes(24)
  var onetime = keypair()
  var keys = symkeys.concat(recipients.map(function (r_pk, i) {
    return scalarmult(onetime.secretKey, r_pk)
  }))

  if(recipients.length + symkeys.length > max)
    throw new Error('max recipients is:'+max+' found:'+recipients.length)

  return exports.multibox_symmetric(msg, nonce, onetime.publicKey, keys, max)

}

exports.multibox_symmetric = function (msg, nonce, pubkey, keys, max) {

  max = setMax(max)

  if(keys.length > max)
    throw new Error('max recipients is:'+max+' found:'+recipients.length)

  var key = randombytes(32)

  var _key = concat([new Buffer([keys.length]), key])

  return concat([
    nonce,
    pubkey,
    concat(keys.map(function (r_key, i) {
      return secretbox(_key, nonce, r_key)
    })),
    secretbox(msg, nonce, key)
  ])

}

exports.decrypt =
exports.multibox_open = function (ctxt, sk, max) { //, groups...
  var onetime_pk = ctxt.slice(24, 24+32)
  var my_key = scalarmult(sk, onetime_pk)
  return exports.multibox_symmetric_open(ctxt, my_key, max)
}

exports.multibox_symmetric_open = function (ctxt, my_key, max) { //, groups...
  max = setMax(max)

  var nonce = ctxt.slice(0, 24)
  var _key, key, length, start = 24+32, size = 32+1+16
  for(var i = 0; i <= max; i++) {
    var s = start+size*i
    if(s + size > (ctxt.length - 16)) continue
    _key = secretbox_open(ctxt.slice(s, s + size), nonce, my_key)
    if(_key) {
      length = _key[0]
      key = _key.slice(1)
      continue
    }
  }

  if(!key) return
  return secretbox_open(ctxt.slice(start+length*size), nonce, key)
}

