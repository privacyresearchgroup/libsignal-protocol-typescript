# Signal Protocol Typescript Library (libsignal-protocol-typescript)

Signal Protocol Typescript implementation based on [libsignal-protocol-javscript](https://github.com/signalapp/libsignal-protocol-javascript).

## ROLFE-TODO

```
/lib                #
/src                # TS source files
/src/__test__       # Tests
```

## Overview

A ratcheting forward secrecy protocol that works in synchronous and
asynchronous messaging environments.

### PreKeys

This protocol uses a concept called 'PreKeys'. A PreKey is an ECPublicKey and
an associated unique ID which are stored together by a server. PreKeys can also
be signed.

At install time, clients generate a single signed PreKey, as well as a large
list of unsigned PreKeys, and transmit all of them to the server.

### Sessions

Signal Protocol is session-oriented. Clients establish a "session," which is
then used for all subsequent encrypt/decrypt operations. There is no need to
ever tear down a session once one has been established.

Sessions are established in one of two ways:

1. PreKeyBundles. A client that wishes to send a message to a recipient can
   establish a session by retrieving a PreKeyBundle for that recipient from the
   server.
1. PreKeySignalMessages. A client can receive a PreKeySignalMessage from a
   recipient and use it to establish a session.

### State

An established session encapsulates a lot of state between two clients. That
state is maintained in durable records which need to be kept for the life of
the session.

State is kept in the following places:

- Identity State. Clients will need to maintain the state of their own identity
  key pair, as well as identity keys received from other clients.
- PreKey State. Clients will need to maintain the state of their generated
  PreKeys.
- Signed PreKey States. Clients will need to maintain the state of their signed
  PreKeys.
- Session State. Clients will need to maintain the state of the sessions they
  have established.

## Requirements (ROLFE-TODO)

This implementation currently depends on the presence of the following
types/interfaces, which are available in most modern browsers.

- [ArrayBuffer](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer)
- [TypedArray](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray)
- [Promise](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise)

## Usage (ROLFE-TODO)
The code samples below come almost directly from our [sample web application]().  Please have a look there to see how everything fits together.  Look at this project's unit tests too.
### Add the SDK to your project
We use [yarn](https://yarnpkg.com).
```
yarn add @privacyresearch/libsignal-protocol-typescript
```
But npm is good too:
```
npm install @privacyresearch/libsignal-protocol-typescript
```
Now you can import classes and functions from the library.  To make the examples below work,  the following import suffices:
```

import { 
    KeyHelper, 
    SignedPublicPreKeyType, 
    SignalProtocolAddress, 
    SessionBuilder, 
    PreKeyType, 
    SessionCipher, 
    MessageType } 
from '@privacyresearch/libsignal-protocol-typescript'
```
If you prefer to use a prefix like `libsignal` and keep a short import, you can do the following:
```
import * as libsignal from '@privacyresearch/libsignal-protocol-typescript'
```
#### Install time

At install time, a signal client needs to generate its identity keys,
registration id, and prekeys.

A signal client also needs to implement a storage interface that will manage
loading and storing of identity, prekeys, signed prekeys, and session state.
See [`src/__test__/storage-type.ts`]() for an example.

Here is what setup might look like:

```ts

    const createID = async (name: string, store: SignalProtocolStore) => {
        const registrationId = KeyHelper.generateRegistrationId()
        storeSomewhereSafe(`registrationID`, registrationId)

        const identityKeyPair = await KeyHelper.generateIdentityKeyPair()
        storeSomewhereSafe('identityKey', identityKeyPair)

        const baseKeyId = makeKeyId()
        const preKey = await KeyHelper.generatePreKey(baseKeyId)
        store.storePreKey(`${baseKeyId}`, preKey.keyPair)

        const signedPreKeyId = makeKeyId()
        const signedPreKey = await KeyHelper.generateSignedPreKey(identityKeyPair, signedPreKeyId)
        store.storeSignedPreKey(signedPreKeyId, signedPreKey.keyPair)
        

        // Now we register this with the server or other directory so all users can see them.
        // You might implement your directory differently, this is not part of the SDK.
        
        const publicSignedPreKey: SignedPublicPreKeyType = {
            keyId: signedPreKeyId,
            publicKey: signedPreKey.keyPair.pubKey,
            signature: signedPreKey.signature
        }
        
        const publicPreKey : PreKeyType = {
            keyId: preKey.keyId,
            publicKey: preKey.keyPair.pubKey
        }
        
        directory.storeKeyBundle(
            name, 
            {
                registrationId,
                identityPubKey: identityKeyPair.pubKey, 
                signedPreKey: publicSignedPreKey, 
                oneTimePreKeys: [publicPreKey]
            }
        )
    }

```
Relevant type definitions and classes: [KeyHelper](), [KeyPairType](), [PreKeyPairType](), [SignedPreKeyPairType](),
[PreKeyType](), [SignedPublicPreKeyType]().

### Building a session

Once this is implemented, building a session is fairly straightforward:

```ts
    const starterMessageBytes = Uint8Array.from([0xce, 0x93, 0xce, 0xb5, 0xce, 0xb9, 0xce, 0xac, 0x20, 0xcf, 0x83, 0xce, 0xbf, 0xcf, 0x85])
    
    const startSessionWithBoris = async () => {
        // get Boris' key bundle. This is a DeviceType<ArrayBuffer>
        const borisBundle = directory.getPreKeyBundle('boris')

        // borisAddress is a SignalProtocolAddress
        const recipientAddress = borisAddress 

        // Instantiate a SessionBuilder for a remote recipientId + deviceId tuple.
        const sessionBuilder = new SessionBuilder(adiStore, recipientAddress)

        // Process a prekey fetched from the server. Returns a promise that resolves
        // once a session is created and saved in the store, or rejects if the
        // identityKey differs from a previously seen identity for this address.
        await sessionBuilder.processPreKey(borisBundle!)

        // Now we can encrypt a messageto get a MessageType object
        const senderSessionCipher = new SessionCipher(adiStore, recipientAddress)
        const ciphertext = await senderSessionCipher.encrypt(starterMessageBytes.buffer)

        // The message is encrypted, now send it however you like.
        sendMessage('boris', 'adalheid', ciphertext)
    
    }
 ```
Relevant type definitions: [DeviceType](), [SignalProtocolAddress](), [MessageType](), [SessionBuilder](), [SessionCipher]()

*Note:* As discussed below, the Signal protocol uses two message types: `PreKeyWhisperMessage` and `WhisperMessage` that are defined
in [the protobuf definitions]() and implemented in [libsignal-protocol-protobuf-ts](https://github.com/privacyresearchgroup/libsignal-protocol-protobuf-ts).  The message created in the sample above is a `PreKeyWhisperMessage`. It carries information needed for the recipient to build a session with the [X3DH Protocol](https://signal.org/docs/specifications/x3dh/). After a session is established for a recipient, `SessionCipher.encrypt()` will return a simpler `WhisperMessage`.

> ***Into the weeds:** The function `sessionCipher.encrypt()` always returns a [`MessageType`]() object. Sometimes it is a `PreKeyWhisperMessage` and sometimes it is a `WhisperMessage`.  To distinguish, check `ciphertext.type`.  If `ciphertext.type === 3` then `ciphertext.body` contains a serialized `PreKeyWhisperMessage`. If `ciphertext.type === 1` then `ciphertext.body` contains a serialized `WhisperMessage`.*

### Encrypting

Once you have a session established with an address, you can encrypt messages
using SessionCipher.

```ts
const plaintext = 'μῆνιν ἄειδε θεὰ Πηληϊάδεω Ἀχιλῆος / οὐλομένην, ἣ μυρί᾽ Ἀχαιοῖς ἄλγε᾽ ἔθηκε'
const buffer = new TextEncoder().encode(plaintext).buffer

const sessionCipher = new SessionCipher(store, address)
const ciphertext = await sessionCipher.encrypt(buffer)
// If we've already established a session, thenciphertext.type === 1.

// Now we can send it over the channel of our choice
sendMessage('adalheid', 'boris', ciphertext) 
```

### Decrypting

Ciphertexts come in two flavors: WhisperMessage and PreKeyWhisperMessage.

```ts
const address = new SignalProtocolAddress(recipientId, deviceId)
const sessionCipher = new SessionCipher(store, address)

// Decrypting a PreKeyWhisperMessage will establish a new session and
// store it in the SignalProtocolStore. It returns a promise that resolves 
// when the message is decrypted or rejects if the identityKey differs from
// a previously seen identity for this address.

let plaintext: ArrayBuffer
// ciphertext: MessageType
if (ciphertext.type === 3) {
   // It is a PreKeyWhisperMessage and will establish a session.
   try {
      plaintext = await sessionCipher.decryptPreKeyWhisperMessage(ciphertext.body!, 'binary')
   } catch (e) {
      // handle identity key conflict
   }
} else if (ciphertext.type === 1) {
   // It is a WhisperMessage for an established session.
   plaintext = await sessionCipher.decryptWhisperMessage(ciphertext.body!, 'binary')
}

// now you can do something with your plaintext, like
const secretMessage = new TextDecoder().decode(new Uint8Array(plaintext))
```
## Injecting Dependencies
This library uses [WebCrypto]() for symmetric key cryptography and random number generation. It uses an implemenation of the [AsyncCurve](https://github.com/privacyresearchgroup/curve25519-typescript/blob/master/src/types.ts#L21) interface in [`curve25519-typescript`](https://github.com/privacyresearchgroup/curve25519-typescript) for public key operations.

Functional defaults are provided for each but you may want to provide your own, either for performance or security reasons.

### WebCrypto defaults and injection
By default this library will use `window.crypto` if it is present.  Otherwise it uses [`msrcrypto`](https://www.npmjs.com/package/msrcrypto).  If you are falling back to `msrcrypto` you will want to consider providing a substitute.

To replace the WebCrypto component with your own, simply call `setWebCrypto` as follows:
```ts
setWebCrypto(myCryptImplementation)
```
Your WebCrypto imlementation does not need to support the entire interface, but does need to implement:
*   AES-CBC
*   HMAC SHA-256
*   `getRandomValues`

### Elliptic curve crypto defaults and injection
By default this library uses the curve X25519 implementation in [`curve25519-typescript`](https://github.com/privacyresearchgroup/curve25519-typescript).  This is a javascript implementation, compiled into [asm.js](http://asmjs.org/) from C with [emscripten](https://emscripten.org/). You may want to provide a native implementation or even use a different curve, like X448.  To do this, wrap your implementation into a an object that implements the [AsyncCurve](https://github.com/privacyresearchgroup/curve25519-typescript/blob/master/src/types.ts#L21) interface and set it as follows:
```ts
setCurve(myCurve)
```


## License

Copyright 2020 by Privacy Research, LLC

Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
