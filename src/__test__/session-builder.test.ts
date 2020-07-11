/* eslint-disable @typescript-eslint/no-non-null-assertion */
import { SessionBuilder } from '../session-builder'
//SESSIONCIPHER import { SessionCipher } from '../session-cipher'
import { SessionRecord } from '../session-record'

import { SignalProtocolAddress } from '../signal-protocol-address'
import { SignalProtocolStore } from './storage-type'

import { generateIdentity, generatePreKeyBundle, assertEqualArrayBuffers } from '../__test-utils__/utils'
import * as utils from '../helpers'
import { KeyHelper } from '../key-helper'
import { SessionCipher } from '../session-cipher'

jest.setTimeout(30000)

const ALICE_ADDRESS = new SignalProtocolAddress('+14151111111', 1)
const BOB_ADDRESS = new SignalProtocolAddress('+14152222222', 1)

const aliceStore = new SignalProtocolStore()
const bobStore = new SignalProtocolStore()
const bobPreKeyId = 1337
const bobSignedKeyId = 1

//-- this was handled in  before(function(done){ code...
const prep = Promise.all([generateIdentity(aliceStore), generateIdentity(bobStore)])
    .then(function () {
        console.log(`generate PreKey bundle`)
        return generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId)
    })
    .then(function (preKeyBundle) {
        const builder = new SessionBuilder(aliceStore, BOB_ADDRESS)
        console.log(`process PreKey`)
        return builder.processPreKey(preKeyBundle)
    })
    .then((s) => {
        console.log(`prepped`)
        return s
    })
//--

const originalMessage = <ArrayBuffer>utils.toArrayBuffer("L'homme est condamné à être libre")
const aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS)
const bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS)

test('basic prekey v3: creates a session', async () => {
    await prep
    console.log(`create a session test`)
    const record = await aliceStore.loadSession(BOB_ADDRESS.toString())
    expect(record).toBeDefined()
    const sessionRecord = SessionRecord.deserialize(record!)
    expect(sessionRecord.haveOpenSession()).toBeTruthy()
    expect(sessionRecord.getOpenSession()).toBeDefined()
})

test('basic prekey v3: the session can encrypt', async () => {
    await prep

    console.log(`encrypt test`)
    const ciphertext = await aliceSessionCipher.encrypt(originalMessage)
    console.log({ ciphertext })
    expect(ciphertext.type).toBe(3) // PREKEY_BUNDLE
    const plaintext = await bobSessionCipher.decryptPreKeyWhisperMessage(ciphertext.body!, 'binary')
    assertEqualArrayBuffers(plaintext, originalMessage) // assertEqualArrayBuffers(plaintext, originalMessage)
})

/*SESSIONCIPHER
test('basic prekey v3: the session can decrypt', async () => {
    await prep
    const ciphertext = await bobSessionCipher.encrypt(originalMessage)
    const plaintext = await aliceSessionCipher.decryptWhisperMessage(ciphertext.body, 'binary')
    assertEqualArrayBuffers(plaintext, originalMessage)
})
*/

test('basic prekey v3: accepts a new preKey with the same identity', async () => {
    await prep
    const preKeyBundle = await generatePreKeyBundle(bobStore, bobPreKeyId + 1, bobSignedKeyId + 1)
    const builder = new SessionBuilder(aliceStore, BOB_ADDRESS)
    console.log(`building prekey for alice again`)
    await builder.processPreKey(preKeyBundle)
    console.log(`builder processed preKey`)
    const record = await aliceStore.loadSession(BOB_ADDRESS.toString())
    expect(record).toBeDefined()
    const sessionRecord = SessionRecord.deserialize(record!)
    expect(sessionRecord.haveOpenSession()).toBeTruthy()
    expect(sessionRecord.getOpenSession()).toBeDefined()
})

test('basic prekey v3: rejects untrusted identity keys', async () => {
    await prep

    console.log(`doReject test 1`)
    const newIdentity = await KeyHelper.generateIdentityKeyPair()
    const builder = new SessionBuilder(aliceStore, BOB_ADDRESS)
    console.log(`reject test 1 processPreKey`)
    await expect(async () => {
        await builder.processPreKey({
            identityKey: newIdentity.pubKey,
            registrationId: 12356,
            signedPreKey: {
                keyId: 2,
                publicKey: new Uint8Array(33).buffer,
                signature: new Uint8Array(32).buffer,
            },
        })
    }).rejects.toThrow('Identity key changed')
})

test('basic v3 NO PREKEY: creates a session', async () => {
    await prep
    const record = await aliceStore.loadSession(BOB_ADDRESS.toString())
    expect(record).toBeDefined()
    const sessionRecord = SessionRecord.deserialize(record!)
    expect(sessionRecord.haveOpenSession()).toBeTruthy()
    expect(sessionRecord.getOpenSession()).toBeDefined()
})

/*SESSIONCIPHER
test('basic v3 NO PREKEY: the session can encrypt', async () => {
    await prep
    const ciphertext = await aliceSessionCipher.encrypt(originalMessage)
    expect(ciphertext.type).toBe(3) // PREKEY_BUNDLE

    const plaintext = await bobSessionCipher.decryptPreKeyWhisperMessage(ciphertext.body, 'binary')

    assertEqualArrayBuffers(plaintext, originalMessage)
})
*/

/*SESSIONCIPHER
test('basic v3 NO PREKEY: the session can decrypt', async () => {
    await prep
    const ciphertext = await bobSessionCipher.encrypt(originalMessage)
    const plaintext = await aliceSessionCipher.decryptWhisperMessage(ciphertext.body, 'binary')
    assertEqualArrayBuffers(plaintext, originalMessage)
})
*/

// test('basic v3 NO PREKEY: accepts a new preKey with the same identity', async () => {
//     await prep
//     const preKeyBundle = await generatePreKeyBundle(bobStore, bobPreKeyId + 1, bobSignedKeyId + 1)
//     delete preKeyBundle.preKey
//     const builder = new SessionBuilder(aliceStore, BOB_ADDRESS)
//     await builder.processPreKey(preKeyBundle)
//     const record = await aliceStore.loadSession(BOB_ADDRESS.toString())
//     expect(record).toBeDefined()
//     const sessionRecord = SessionRecord.deserialize(record!)
//     expect(sessionRecord.haveOpenSession()).toBeTruthy()
//     expect(sessionRecord.getOpenSession()).toBeDefined
// })

test('basic v3 NO PREKEY: rejects untrusted identity keys', async () => {
    await prep
    console.log(`doReject test 2`)

    const newIdentity = await KeyHelper.generateIdentityKeyPair() //.then(function (newIdentity) {
    const builder = new SessionBuilder(aliceStore, BOB_ADDRESS)

    console.log(`reject test 2 processPreKey`)
    await expect(async () => {
        await builder.processPreKey({
            identityKey: newIdentity.pubKey,
            registrationId: 12356,
            signedPreKey: {
                keyId: 2,
                publicKey: new Uint8Array(33).buffer,
                signature: new Uint8Array(32).buffer,
            },
        })
    }).rejects.toThrow('Identity key changed')
})
