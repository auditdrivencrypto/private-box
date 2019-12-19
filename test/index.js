
var tape = require('tape')
var crypto = require('crypto')

var c = require('../')
var sodium = require('chloride')

var keypair = sodium.crypto_box_keypair

var alice = keypair()
var bob   = keypair()

function arrayOfSize (n) {
  return new Array(n+1).join('0').split('')
}

tape('simple', function (t) {

  var msg = new Buffer('hello there!')
  var ctxt = c.multibox(msg, [alice.publicKey, bob.publicKey])
  console.log(ctxt)

  ;[alice.secretKey, bob.secretKey].forEach(function (sk) {

    console.log(ctxt, sk)
    var _msg = c.multibox_open(ctxt, sk)

    t.deepEqual(_msg, msg)

  })

  t.end()
})

tape('errors when too many recipients', function (t) {
  var msg = new Buffer('hello there!')
  var pk = alice.publicKey
  t.throws(function () {
      c.multibox(msg, [
        pk,pk,pk,pk,
        pk,pk,pk,pk,
        pk,pk,pk,pk,
        pk,pk,pk,pk
      ])
  })
  t.end()
})

function encryptDecryptTo (n, t) {
  var msg = crypto.randomBytes(1024)
  var keys = arrayOfSize(n).map(function () { return keypair() })

  var ctxt = c.multibox(msg, keys.map(function (e) { return e.publicKey }), n)

  // a recipient key may open the message.
  keys.forEach(function (keys) {
    t.deepEqual(c.multibox_open(ctxt, keys.secretKey, n), msg)
  })

  t.equal(c.multibox_open(ctxt, keypair().secretKey), undefined)
}

tape('with no custom max set, encrypt/decrypt to 7 keys', function (t) {
  encryptDecryptTo(7, t)
  t.end()
})

tape('can encrypt/decrypt up to 255 recipients after setting a custom max', function (t) {
  encryptDecryptTo(255, t)
  t.end()
})


tape('errors when max is more than 255 or less than 1', function (t) {
  var msg = new Buffer('hello there!')
  var ctxt = c.multibox(msg, [alice.publicKey, bob.publicKey])
  var pk = alice.publicKey
  var sk = alice.secretKey
  t.throws(function () {
      c.multibox(msg, [
        pk,pk,pk,pk,
      ], -1)
  })
  t.throws(function () {
      c.multibox.open(ctxt, sk, 256)
  })
  t.end()
})
