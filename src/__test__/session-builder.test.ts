import { SessionBuilder } from '../session-builder'
//TODO import { SessionCipher } from '../session-cipher'
import { SessionRecord } from '../session-record'

import { SignalProtocolAddress } from '../signal-protocol-address'
import { SignalProtocolStore } from './storage-type'

import { generateIdentity, generatePreKeyBundle } from '../__test-utils__/utils'
import * as utils from '../helpers'

const ALICE_ADDRESS = new SignalProtocolAddress('+14151111111', 1)
const BOB_ADDRESS = new SignalProtocolAddress('+14152222222', 1)

const aliceStore = new SignalProtocolStore()
const bobStore = new SignalProtocolStore()
const bobPreKeyId = 1337
const bobSignedKeyId = 1

//-- this was handled in  before(function(done){ code...
const prep = Promise.all([generateIdentity(aliceStore), generateIdentity(bobStore)])
    .then(function () {
        return generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId)
    })
    .then(function (preKeyBundle) {
        const builder = new SessionBuilder(aliceStore, BOB_ADDRESS)
        return builder.processPreKey(preKeyBundle)
    })
//--

const originalMessage = utils.toArrayBuffer("L'homme est condamné à être libre")
//TODO const aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS)
//TODO const bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS)

test('basic prekey v3: creates a session', async () => {
    await prep
    const record = await aliceStore.loadSession(BOB_ADDRESS.toString())
    expect(record).toBeDefined()
    const sessionRecord = SessionRecord.deserialize(record)
    expect(sessionRecord.haveOpenSession()).toBeTruthy()
    expect(sessionRecord.getOpenSession()).toBeDefined()
})
/*
test('basic prekey v3: the session can encrypt', function (done) {
        await prep

    aliceSessionCipher
        .encrypt(originalMessage)
        .then(function (ciphertext) {
            assert.strictEqual(ciphertext.type, 3) // PREKEY_BUNDLE

            return bobSessionCipher.decryptPreKeyWhisperMessage(ciphertext.body, 'binary')
        })
        .then(function (plaintext) {
            assertEqualArrayBuffers(plaintext, originalMessage)
        })
        .then(done, done)
})

test('basic prekey v3: the session can decrypt', function (done) {
       await prep

    bobSessionCipher
        .encrypt(originalMessage)
        .then(function (ciphertext) {
            return aliceSessionCipher.decryptWhisperMessage(ciphertext.body, 'binary')
        })
        .then(function (plaintext) {
            assertEqualArrayBuffers(plaintext, originalMessage)
        })
        .then(done, done)
})

test('basic prekey v3: accepts a new preKey with the same identity', function (done) {
      await prep

    generatePreKeyBundle(bobStore, bobPreKeyId + 1, bobSignedKeyId + 1)
        .then(function (preKeyBundle) {
            const builder = new SessionBuilder(aliceStore, BOB_ADDRESS)
            return builder.processPreKey(preKeyBundle).then(function () {
                return aliceStore.loadSession(BOB_ADDRESS.toString()).then(function (record) {
                    assert.isDefined(record)
                    const sessionRecord = SessionRecord.deserialize(record)
                    assert.isTrue(sessionRecord.haveOpenSession())
                    assert.isDefined(sessionRecord.getOpenSession())
                    done()
                })
            })
        })
        .catch(done)
})

test('basic prekey v3: rejects untrusted identity keys', function (done) {
     await prep

    KeyHelper.generateIdentityKeyPair().then(function (newIdentity) {
        const builder = new SessionBuilder(aliceStore, BOB_ADDRESS)
        return builder
            .processPreKey({
                identityKey: newIdentity.pubKey,
                registrationId: 12356,
            })
            .then(function (e) {
                assert.fail('should not be trusted')
            })
            .catch(function (e) {
                assert.strictEqual(e.message, 'Identity key changed')
                done()
            })
            .catch(done)
    })
})
//})

//describe('basic v3 NO PREKEY', function () {
//    const aliceStore = new SignalProtocolStore()

//   const bobStore = new SignalProtocolStore()
//   const bobPreKeyId = 1337
//   const bobSignedKeyId = 1

//    const Curve = libsignal.Curve

before(function (done) {
     await prep

    Promise.all([generateIdentity(aliceStore), generateIdentity(bobStore)])
        .then(function () {
            return generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId)
        })
        .then(function (preKeyBundle) {
            delete preKeyBundle.preKey
            const builder = new SessionBuilder(aliceStore, BOB_ADDRESS)
            return builder.processPreKey(preKeyBundle).then(function () {
                done()
            })
        })
        .catch(done)
})

// const originalMessage = util.toArrayBuffer("L'homme est condamné à être libre")
// const aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS)
// const bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS)

test('basic v3 NO PREKEY: creates a session', function (done) {
       await prep

    return aliceStore
        .loadSession(BOB_ADDRESS.toString())
        .then(function (record) {
            assert.isDefined(record)
            const sessionRecord = SessionRecord.deserialize(record)
            assert.isTrue(sessionRecord.haveOpenSession())
            assert.isDefined(sessionRecord.getOpenSession())
        })
        .then(done, done)
})

test('basic v3 NO PREKEY: the session can encrypt', function (done) {
       await prep

    aliceSessionCipher
        .encrypt(originalMessage)
        .then(function (ciphertext) {
            assert.strictEqual(ciphertext.type, 3) // PREKEY_BUNDLE

            return bobSessionCipher.decryptPreKeyWhisperMessage(ciphertext.body, 'binary')
        })
        .then(function (plaintext) {
            assertEqualArrayBuffers(plaintext, originalMessage)
        })
        .then(done, done)
})

test('basic v3 NO PREKEY: the session can decrypt', function (done) {
       await prep

    bobSessionCipher
        .encrypt(originalMessage)
        .then(function (ciphertext) {
            return aliceSessionCipher.decryptWhisperMessage(ciphertext.body, 'binary')
        })
        .then(function (plaintext) {
            assertEqualArrayBuffers(plaintext, originalMessage)
        })
        .then(done, done)
})

test('basic v3 NO PREKEY: accepts a new preKey with the same identity', function (done) {
     await prep

    generatePreKeyBundle(bobStore, bobPreKeyId + 1, bobSignedKeyId + 1)
        .then(function (preKeyBundle) {
            delete preKeyBundle.preKey
            const builder = new SessionBuilder(aliceStore, BOB_ADDRESS)
            return builder.processPreKey(preKeyBundle).then(function () {
                return aliceStore.loadSession(BOB_ADDRESS.toString()).then(function (record) {
                    assert.isDefined(record)
                    const sessionRecord = SessionRecord.deserialize(record)
                    assert.isTrue(sessionRecord.haveOpenSession())
                    assert.isDefined(sessionRecord.getOpenSession())
                    done()
                })
            })
        })
        .catch(done)
})

test('basic v3 NO PREKEY: rejects untrusted identity keys', function (done) {
      await prep

    KeyHelper.generateIdentityKeyPair().then(function (newIdentity) {
        const builder = new SessionBuilder(aliceStore, BOB_ADDRESS)
        return builder
            .processPreKey({
                identityKey: newIdentity.pubKey,
                registrationId: 12356,
            })
            .then(function (e) {
                assert.fail('should not be trusted')
            })
            .catch(function (e) {
                assert.strictEqual(e.message, 'Identity key changed')
                done()
            })
            .catch(done)
    })
})
//})
// })
*/
