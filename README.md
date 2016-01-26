# private-box

format for encrypting a private message between from 1 to many parties.
`private-box` is designed according to the [auditdrivencrypto design process](https://github.com/crypto-browserify/crypto-browserify/issues/128)

## API

### encrypt (plaintext Buffer, recipients Array<curve25519_pk>)

Take a `plaintext` Buffer of the message you want to encrypt,
and an array of recipient public keys.
Returns a message that is encrypted to all recipients
and openable by them with `PrivateBox.decrypt`.
The `recipients` must be between 1 and 7 items long.

The encrypted length will be between `56 + (recipients.length * 33) + plaintext.length` bytes long.
(minimum 89 and maximum 287 bytes longer than the plaintext)

### decrypt (cyphertext Buffer, secretKey curve25519_sk)

Attempt to decrypt a private-box message, using your secret key.
If you where an intended recipient then the plaintext will be returned.
If it was not for you, then `undefined` will be returned.

## protocol

### encryption

`private-box` generates an ephemeral curve25519 keypair that will only be used with this message (`ephemeral_keys`),
and a random `key` that will be used to encrypt the plaintext body (`body_key`).
first, private-box outputs the ephemeral public key, then takes each recipient public key and 
multiplies it with the ephemeral private key to produce ephemeral shared keys (`shared_keys[1..n]`).
Then private-box concatenates `body_key` with the number of recipients,
and then encrypts that to each shared key, then concatenates the encrypted body.

```
function encrypt (plaintext, recipients) {
  var ephemeral = keypair()
  var nonce     = random(24)
  var key       = random(32)
  var key_with_length = concat([key, recipients.length])
  return concat([
    nonce,
    ephemeral.publicKey,
    concat(recipients.map(function (publicKey) {
      return secretbox(
        key_with_length,
        nonce,
        scalarmult(publicKey, ephemeral.secretKey)
      )
    }),
    secretbox(plaintext, nonce, key)
  ])
}
```

## decrypt

private-box takes the nonce and ephemeral public key,
multiplies that with your secret key, then tests each possible
recipient slot until it either decrypts a key or runs out of slots.
If it runs out of slots, the message was not addressed to you,
so `undefined` is returned. Else, the message is found and the body
is decrypted.

``` js
function decrypt (cyphertext, secretKey) {
  var next = reader(cyphertext) //reader returns a function that 
  var nonce = next(24)
  var publicKey = next(32)
  var sharedKey = salarmult(publicKey, secretKey)

  for(var i = 0; i < 7; i++) {
    var maybe_key = next(33)
    var key_with_length = secretbox_open(maybe_key, nonce, sharedKey)
    if(key_with_length) {//decrypted!
      var key = key_with_length.slice(0, 32)
      var length = key_with_length[32]
      return secretbox_open(
        key,
        cyphertext.slice(56 + 33*(length+1), cyphertext.length),
      )
    }
  }
  //this message was not addressed to the owner of secretKey
  return undefined
}
```

## Assumptions

Messages will be posted in public, so that the sender is likely to be known,
but everyone can read the messages. (this makes it possible to hide the recipient,
but probably not the sender)

Resisting traffic analysis of the timing or size of messages is out of scope of this spec.

## Prior Art

### pgp

In pgp the recipient, the sender, and the subject are sent as plaintext.
If the recipient is known then the metadata graph of who is communicating with who can be read,
which, since it is easier to analyze than the content, is important to protect.

### sodium seal

The sodium library provides a _seal_ function that generates an ephemeral keypair,
derives a shared key to encrypt a message, and then sends the ephemeral public key and the message.
The recipient is hidden, and it is forward secure if the sender throws out the ephemeral key.
However, it's only possible to have one recipient.

### minilock

minilock uses a similar approach to `private-box` but does not hide the
number of recipients. In the case of a group discussion where multiple rounds
of messages are sent to everyone, this may enable an eavesdropper to deanonymize
the participiants of a discussion if the sender of each message is known.

## Properties

This protocol was designed for use with secure-scuttlebutt,
in this place, messages are placed in public, and the sender is known.
(via a signature) but we can hide the recipient and the content.

### recipients are hidden.

An eaves dropper cannot know the recipients or their number.
since the message is encrypted to each recipient, and then placed in public,
to receive a message you will have to decrypt every message posted.
This would not be scalable if you had to decrypt every message on the internet,
but if you can restrict the number of messages you might have to decrypt,
then it's reasonable. For example, if you frequented a forum which contained these messages,
then it would only be a reasonable number of messages, and posting a message would only
reveal that you where talking to some other member of that forum.
Hiding access to such a forum is another problem, out of the current scope.

### the number of recipients are hidden.

If the number of recipients was not hidden, then sometimes it would be possible
to deanonymise the number of recipients, if there was a large group discussion with
an unusual number of recipients. Encrypting the number of recipients means that
when you fail to decrypt a message you must attempt to decrypt same number of times
as the maximum recipients.

### a valid recipient does not know the other recipients.

A valid recipient knows the number of recipients but now who they are.
This is more a sideeffect of the design than an intentional design element.

### by providing the `key` for a message a outside party could decrypt the message.

When you tell someone a secret you must trust them not to reveal it.
Anyone who knows the `key` could reveal that to some other party who could then read the message content,
but not the recipients (unless the sender revealed the ephemeral secret key)

## License

MIT








