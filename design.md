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

### time complexity

failed decrypt: recipients.length
successful decrypt: recipients.length/2

## a more private multibox

The properties might get a bit cleaner

``` js

function multibox2 (msg, nonce, recipients) {

  var key = random(32)
  //MAX 16 recipients
  var _key = concat([new Buffer([(recipients.length-1) && 15]), key)
  var onetime = box_keypair()

  return concat([
    nonce, //24 bytes
    onetime.publicKey, //32 bytes
            //recipients.length * 16+33
    recipients.map(function (r_pk) {
      return box(_key, nonce, r_pk, onetime.secretKey)
    }),
    //msg.length + 16
    secretbox_easy(msg, nonce, key)
  ])
}
```

An interesting property of this is that the recipient
identities are forward secure (though, since I am assuming
that the sender encrypts this message back to themself,
whoever has their private key can read the message, and
those id's are likely written in the message)

Note, here that the recipient length field is encrypted to each
recipient! If the number of recipients is not hidden,
and I send a group message to a weird number, then someone
hits "reply-all" it would suggest it was a reply.
By hiding the number of "to" addresses, the messages will be _very private_.

They will be more expensive to calculate, but since an `secretbox_open`
attempt is actually very cheap (about 50 make 1 `scalarmult` op)
so if you have 1 asym operation, then doing less than say, 50
unboxes won't matter much.
[see sodiumperf tests](https://github.com/dominictarr/sodiumperf)

So this wouldn't be very much slower than any of the above
algorithms, but it would be more private, even though it supports
multiple recipients. Also, since the encrypted message has a one-off
key, you could reveal the key to one message... if you needed
to prove someone was harassing you, for example. Or, if you wanted
to implement moderated groups, you could post a message to the moderator
who would then reveal the key for that message to the group.

Decrypt might look like this:

``` js
function multibox2_open (ctxt, sk) {
  var nonce = ctxt.slice(0, 24)
  var onetime_pk = ctxt.slice(24, 24+32)
  var my_key = scalarmult(sk, onetime_pk)
  //try a bunch of keys
  var _key, start = 24+32, keysize = 16+1+32
  for(var i = 0; i < 8 || !key; i++) {
    var s = start+(keysize*i), e = s + keysize
    _key = secretbox_easy_open(ctxt.slice(s, e), nonce, my_key)
  }
  if(!key) return //message not addressed to us

  var length = key[0]
  var rest = ctxt.slice(start + keysize*length, ctxt.length)

  return secretbox_easy_open(rest, nonce, key.slice(1, 33))
}

```

## Groups

Often we want to communicate not just with individuals, but with groups.
Although if more actors know the secret, then it's less secure.

I can see two ways this could work,

### One Way Groups

an author delegates a read cap (key) to selected peers,
and then posts messages that holders of that key can read.
The dynamic here is similar to facebook - if I add you
as my friend then you can read my posts.

When a peer is decrypting messages, they will try the keys
on each message received from that author. In most cases,
a given actor will create a handful of groups (friends, family, work,
hobby group, etc) and any other peer is probably only a member
of one or two of those.

The cost of this would be `groups_added*max_groups`,
the max number of groups a message should be broadcast to
should probably be very small, like 2 or 3, then if
A adds B to 3 groups, B will only need to attempt 9 unboxings
to read a message.

### Shared Groups

In othercases, there are groups of people who do not personally
know each other form around a common interest. Facebook groups
work like this.

In this situation, it could be quite complicated to know what
groups a given actor is in. For example, A creates group G,
then adds B, who adds C. C then posts a message to group G.
suppose that A sees C's message before she hears from A that
C is now a member of G. Either A dosen't know to try G_key on
C's message, or A just tries every group key on every message A sees.

As long as A is not a member of more than a few groups, this is not
too much of a problem. But, if there are two types of groups,
then G that could be many groups to check. Probably the simplest
way to mitigate this is _prevent cross posting_, allow only one
shared group per message, then only check for group keys
on the first slot!

## License

MIT
