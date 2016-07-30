
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
exports.multibox = function (msg, recipients, max) {

  max = setMax(max)

  if(recipients.length > max)
    throw new Error('max recipients is:'+max+' found:'+recipients.length)

  var nonce = randombytes(24)
  var key = randombytes(32)
  var onetime = keypair()

  var _key = concat([new Buffer([recipients.length & max]), key])
  return concat([
    nonce,
    onetime.publicKey,
    concat(recipients.map(function (r_pk, i) {
      return secretbox(_key, nonce, scalarmult(onetime.secretKey, r_pk))
    })),
    secretbox(msg, nonce, key)
  ])
}

function get_key(ctxt, my_key) {

}

exports.decrypt =
exports.multibox_open = function (ctxt, sk, max) { //, groups...

  max = setMax(max)

  var nonce = ctxt.slice(0, 24)
  var onetime_pk = ctxt.slice(24, 24+32)
  var my_key = scalarmult(sk, onetime_pk)
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

