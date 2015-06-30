# private-box

an unaddressed box, with a private note-to-self so the sender can remember who it was for.

``` js

private_box(msg, nonce, recipient_pk, sender_sk, sender_key) => ciphertext

//then, the receiver can open it if they know the sender.

private_unbox(msg, nonce, sender_pk, recipient_sk) => plaintext

//OR, the sender can decrypt.

private_unbox2(msg, nonce, sender_sk, sender_key) => plaintext

```

In secure scuttlebutt, a potential receiver knows who posted
a message, because it has a pk/signature. The envelope is marked
with a _from_ field, but there is no _to_ field.

However, sometimes the sender needs to look at a message
they sent. If there is no _to_ field, the sender must encrypt
a short message _to themselves_.

## generate one time key.

generate a onetime keypair, box a message to the receipient
with it, and also box a message back to your self, including
the onetime secret, so that you can reopen the message if necessary.

```js
//two scalarmult + key_pair
//152 byte overhead
function private_box (msg, nonce, recipient_pk, sender_sk) {
  var onetime = box_keypair()
  return concat([
    nonce,                   //24 bytes
    onetime.publicKey,       //32 bytes
    box_easy(                //32+32+16 = 80 bytes
      concat([recipient_pk, onetime.secretKey]),
      onetime.publicKey,
      sender_sk
    ),
                             //msg.length + 16 bytes
    box_easy(msg, nonce, recipient_pk, onetime.secretKey)
  ]
}
```
this design generates a new key pair on ever write,
and then uses two scalarmult operations.
there are 152 bytes of overhead.

One interesting benefit is that you could have a oneway
write, where the author forgets the onetime secret key,
so the box can only be opened by it's recipient.

## keep a symmetric key for the note-to-self

We have to keep track of another secret key
(it could be derived from the private key, though)

``` js

function private_box (msg, nonce, recipient_pk, sender_sk, sender_key) {
  return concat([
    nonce,                                           //24 bytes
    secretbox_easy(recipient_pk, nonce, sender_key), //32+16=40 bytes
    box_easy(msg, nonce, recipient_pk, sender_sk)    //msg.length + 16
  ])
}
```

Only 80 bytes overhead (just over half as much) and only one
scalarmult. This will be a more performant encrypt operation,
but decrypt will be only slightly better.

This construction could be used to store encrypted messages
for yourself, by "sending them" to a onetime key.

Also, it would mean that `sender_key` is 

## one way box

you could have a box that only the recipient can open.

``` js
function oneway_box (msg, nonce, recipient_pk) {
  var onetime = keypair()
  return concat([
    nonce,
    onetime.publicKey,
    box_easy(msg, nonce, recipient_pk, onetime.secretKey)
  ])
}
```
This would have the interesting property that the message
could not be opened by the sender (once they have deleted
`onetime.secretKey`)

This doesn't seem very useful for a database.

## multiple recipients

maybe, a way to generalize this would be to have multiple
recipients?

``` js

function multibox (msg, nonce, recipients, sender_sk) {

  var key = random(32)

  return concat([
    nonce, //24 bytes
           //1 byte
    new Buffer([recipients.length & 255]), //MAX 1 byte!
            //recipients.length * 16+32
    recipients.map(function (r_pk) {
      return box(key, nonce, r_pk, sender_sk)
    }),
    //msg.length + 16
    secretbox_easy(msg, nonce, key)
  ])
}

```

So, to use this model, you would normally make the first recipient
your self. This would support messages to N recipients,
and also support one way messages, or messages to yourself.

To decrypt, you would take `scalarmult(your_sk, sender_pk)`
and then use that to unbox recipients until you get a valid
mac. This could be pretty fast, because there would be only one
curve op, and then the rest is symmetric crypto.


## License

MIT
