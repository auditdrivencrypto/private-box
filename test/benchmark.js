
var chloride = require('chloride')
var crypto = require('crypto')
var box = require('../')

var content = crypto.randomBytes(1024)
var alice = chloride.crypto_box_keypair()
var bob = chloride.crypto_box_keypair()
function create (n, content, pk, max) {
  var a = [pk]
  for(var i = 1; i < n; i++) {
    a.push(chloride.crypto_box_keypair().publicKey)
  }
  return box.encrypt(content, a, max)
}

console.log(alice)
console.log()

function bench (max, N) {
  var ctxt = create(max, content, alice.publicKey, max)
  console.log('max:', max) //number of recipients
  //length of cyphertext, ratio of cyphertext to plaintext length
  console.log('length', ctxt.length, ctxt.length/content.length)
  var start = Date.now()
  for(var i = 0; i < N; i++)
    box.decrypt(ctxt, alice.secretKey, max)
  var hit = Date.now() - start
  console.log('hit', hit/N) //ms to decrypt a message that was for us

  var start = Date.now()
  for(var i = 0; i < N; i++)
    box.decrypt(ctxt, bob.secretKey, max)
  var miss = Date.now() - start
  console.log('miss', miss/N) //ms to fail to decrypt a message not for us

  console.log('ratio', miss/hit) //how much miss is bigger than hit.
}

var N = 10000
bench(8, N)
bench(16, N)
bench(32, N)
bench(64, N)
bench(128, N)
