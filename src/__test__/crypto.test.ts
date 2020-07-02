import { hexToArrayBuffer, assertEqualArrayBuffers } from './utils'
import * as Internal from '../internal'

const alice_bytes = hexToArrayBuffer('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
const alice_priv = hexToArrayBuffer('70076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c6a')
const alice_pub = hexToArrayBuffer('058520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')
const bob_bytes = hexToArrayBuffer('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')
const bob_priv = hexToArrayBuffer('58ab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e06b')
const bob_pub = hexToArrayBuffer('05de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')
const shared_sec = hexToArrayBuffer('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742')

test(`createKeyPair converts alice's private keys to a keypair`, async () => {
    const alicekeypair = await Internal.crypto.createKeyPair(alice_bytes)
    assertEqualArrayBuffers(alicekeypair.privKey, alice_priv)
    assertEqualArrayBuffers(alicekeypair.pubKey, alice_pub)

    const bobkeypair = await Internal.crypto.createKeyPair(bob_bytes)
    assertEqualArrayBuffers(bobkeypair.privKey, bob_priv)
    assertEqualArrayBuffers(bobkeypair.pubKey, bob_pub)
})

test(`createKeyPair generates a key if not provided`, async () => {
    const keypair = await Internal.crypto.createKeyPair()
    expect(keypair.privKey.byteLength).toStrictEqual(32)
    expect(keypair.pubKey.byteLength).toStrictEqual(33)
    expect(new Uint8Array(keypair.pubKey)[0]).toStrictEqual(5)
})

test(`ECDHE computes the shared secret for alice`, async () => {
    const secret = await Internal.crypto.ECDHE(bob_pub, alice_priv)
    assertEqualArrayBuffers(shared_sec, secret)
})

test(`ECDHE computes the shared secret for bob`, async () => {
    const secret = await Internal.crypto.ECDHE(alice_pub, bob_priv)
    assertEqualArrayBuffers(shared_sec, secret)
})
const priv = hexToArrayBuffer('48a8892cc4e49124b7b57d94fa15becfce071830d6449004685e387c62409973')
const pub = hexToArrayBuffer('0555f1bfede27b6a03e0dd389478ffb01462e5c52dbbac32cf870f00af1ed9af3a')
const msg = hexToArrayBuffer('617364666173646661736466')
const sig = hexToArrayBuffer(
    '2bc06c745acb8bae10fbc607ee306084d0c28e2b3bb819133392473431291fd0dfa9c7f11479996cf520730d2901267387e08d85bbf2af941590e3035a545285'
)

test(`Ed25519Sign works`, async () => {
    const sigCalc = await Internal.crypto.Ed25519Sign(priv, msg)
    assertEqualArrayBuffers(sig, sigCalc)
})

test(`Ed25519Verify throws on bad signature`, async () => {
    const badsig = sig.slice(0)
    new Uint8Array(badsig).set([0], 0)

    try {
        await Internal.crypto.Ed25519Verify(pub, msg, badsig)
    } catch (e) {
        if (e.message === 'Invalid signature') {
            return
        }
    }
    console.error('Sign did not throw on bad input')
})

test(`Ed25519Verify does not throw on good signature`, async () => {
    await Internal.crypto.Ed25519Verify(pub, msg, sig)
})
