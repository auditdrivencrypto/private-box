
var tape = require('tape')
var crypto = require('crypto')

var c = require('../')
var sodium = require('chloride/build/Release/sodium')

var keypair = sodium.crypto_box_keypair

var alice = keypair()
var bob   = keypair()

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

tape('encrypt/decrypt to many keys', function (t) {
  var msg = crypto.randomBytes(1024)
  var keys = [1,2,3,4,5,6,7].map(function () { return keypair() })

  var ctxt = c.multibox(msg, keys.map(function (e) { return e.publicKey }))

  // a recipient key may open the message.
  keys.forEach(function (keys) {
    t.deepEqual(c.multibox_open(ctxt, keys.secretKey), msg)
  })

  t.equal(c.multibox_open(ctxt, keypair().secretKey), undefined)

  t.end()
})


