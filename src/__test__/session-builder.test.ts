/* eslint-disable @typescript-eslint/no-non-null-assertion */
import { generatePreKeyBundle, generateIdentity } from '../__test-utils__/utils'
import { KeyHelper } from '../key-helper'
import { SessionBuilder } from '../session-builder'
import { SessionRecord } from '../session-record'
import { SignalProtocolAddress } from '..'
import { SignalProtocolStore } from './storage-type'

// import * as util from '../helpers'
// const ALICE_ADDRESS = new SignalProtocolAddress('+14151111111', 1)
const BOB_ADDRESS = new SignalProtocolAddress('+14152222222', 1)
const aliceStore = new SignalProtocolStore()

const bobStore = new SignalProtocolStore()
const bobPreKeyId = 1337
const bobSignedKeyId = 1
// const originalMessage = util.toArrayBuffer("L'homme est condamné à être libre")

// jest.setTimeout(60 * 1000)
beforeAll(async () => {
    try {
        console.log(`beforeAll start`)
        await Promise.all([generateIdentity(aliceStore), generateIdentity(bobStore)])
        console.log(`generated IDs`)
        const preKeyBundle = await generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId)
        console.log(`generated prekey bundle`)
        const builder = new SessionBuilder(aliceStore, BOB_ADDRESS)
        console.log(`begin session-record tests: process PreKey`)
        const s1 = await builder.processPreKey(preKeyBundle)
        console.log(`begin session-record tests`, { s1 })
    } catch (e) {
        console.error(e)
    }
})

describe('SessionBuilder', () => {
    describe('basic prekey v3', () => {
        // const Curve = libsignal.Curve

        // const aliceSessionCipher = new libsignal.SessionCipher(aliceStore, BOB_ADDRESS)
        // const bobSessionCipher = new libsignal.SessionCipher(bobStore, ALICE_ADDRESS)

        test('creates a session', async () => {
            const record = await aliceStore.loadSession(BOB_ADDRESS.toString())
            expect(record).toBeDefined()
            const sessionRecord = SessionRecord.deserialize(record!)
            expect(sessionRecord.haveOpenSession()).toBe(true)
            expect(sessionRecord.getOpenSession()).toBeDefined()
        })

        // it('the session can encrypt', function (done) {
        //     aliceSessionCipher
        //         .encrypt(originalMessage)
        //         .then(function (ciphertext) {
        //             assert.strictEqual(ciphertext.type, 3) // PREKEY_BUNDLE

        //             return bobSessionCipher.decryptPreKeyWhisperMessage(ciphertext.body, 'binary')
        //         })
        //         .then(function (plaintext) {
        //             assertEqualArrayBuffers(plaintext, originalMessage)
        //         })
        //         .then(done, done)
        // })

        // it('the session can decrypt', function (done) {
        //     bobSessionCipher
        //         .encrypt(originalMessage)
        //         .then(function (ciphertext) {
        //             return aliceSessionCipher.decryptWhisperMessage(ciphertext.body, 'binary')
        //         })
        //         .then(function (plaintext) {
        //             assertEqualArrayBuffers(plaintext, originalMessage)
        //         })
        //         .then(done, done)
        // })

        test('accepts a new preKey with the same identity', async () => {
            await generatePreKeyBundle(bobStore, bobPreKeyId + 1, bobSignedKeyId + 1).then(function (preKeyBundle) {
                const builder = new SessionBuilder(aliceStore, BOB_ADDRESS)
                return builder.processPreKey(preKeyBundle).then(function () {
                    return aliceStore.loadSession(BOB_ADDRESS.toString()).then(function (record) {
                        expect(record).toBeDefined()
                        const sessionRecord = SessionRecord.deserialize(record!)
                        expect(sessionRecord.haveOpenSession()).toBe(true)
                        expect(sessionRecord.getOpenSession()).toBeDefined()
                    })
                })
            })
        })

        test('rejects untrusted identity keys', async () => {
            const newIdentity = await KeyHelper.generateIdentityKeyPair()
            const builder = new SessionBuilder(aliceStore, BOB_ADDRESS)

            await expect(() => {
                return builder.processPreKey({
                    identityKey: newIdentity.pubKey,
                    registrationId: 12356,
                    signedPreKey: {
                        keyId: 2,
                        publicKey: new Uint8Array(33).buffer,
                        signature: new Uint8Array(32).buffer,
                    },
                })
            }).rejects.toThrow() // 'Identity key changed'
        })
    })

    // describe('basic v3 NO PREKEY', function () {
    //     const aliceStore = new SignalProtocolStore()

    //     const bobStore = new SignalProtocolStore()
    //     const bobPreKeyId = 1337
    //     const bobSignedKeyId = 1

    //     const Curve = libsignal.Curve

    //     before(function (done) {
    //         Promise.all([generateIdentity(aliceStore), generateIdentity(bobStore)])
    //             .then(function () {
    //                 return generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId)
    //             })
    //             .then(function (preKeyBundle) {
    //                 delete preKeyBundle.preKey
    //                 const builder = new SessionBuilder(aliceStore, BOB_ADDRESS)
    //                 return builder.processPreKey(preKeyBundle).then(function () {
    //                     done()
    //                 })
    //             })
    //             .catch(done)
    //     })

    //     const originalMessage = util.toArrayBuffer("L'homme est condamné à être libre")
    //     const aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS)
    //     const bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS)

    //     it('creates a session', function (done) {
    //         return aliceStore
    //             .loadSession(BOB_ADDRESS.toString())
    //             .then(function (record) {
    //                 assert.isDefined(record)
    //                 const sessionRecord = Internal.SessionRecord.deserialize(record)
    //                 assert.isTrue(sessionRecord.haveOpenSession())
    //                 assert.isDefined(sessionRecord.getOpenSession())
    //             })
    //             .then(done, done)
    //     })

    //     it('the session can encrypt', function (done) {
    //         aliceSessionCipher
    //             .encrypt(originalMessage)
    //             .then(function (ciphertext) {
    //                 assert.strictEqual(ciphertext.type, 3) // PREKEY_BUNDLE

    //                 return bobSessionCipher.decryptPreKeyWhisperMessage(ciphertext.body, 'binary')
    //             })
    //             .then(function (plaintext) {
    //                 assertEqualArrayBuffers(plaintext, originalMessage)
    //             })
    //             .then(done, done)
    //     })

    //     it('the session can decrypt', function (done) {
    //         bobSessionCipher
    //             .encrypt(originalMessage)
    //             .then(function (ciphertext) {
    //                 return aliceSessionCipher.decryptWhisperMessage(ciphertext.body, 'binary')
    //             })
    //             .then(function (plaintext) {
    //                 assertEqualArrayBuffers(plaintext, originalMessage)
    //             })
    //             .then(done, done)
    //     })

    //     it('accepts a new preKey with the same identity', function (done) {
    //         generatePreKeyBundle(bobStore, bobPreKeyId + 1, bobSignedKeyId + 1)
    //             .then(function (preKeyBundle) {
    //                 delete preKeyBundle.preKey
    //                 const builder = new libsignal.SessionBuilder(aliceStore, BOB_ADDRESS)
    //                 return builder.processPreKey(preKeyBundle).then(function () {
    //                     return aliceStore.loadSession(BOB_ADDRESS.toString()).then(function (record) {
    //                         assert.isDefined(record)
    //                         const sessionRecord = Internal.SessionRecord.deserialize(record)
    //                         assert.isTrue(sessionRecord.haveOpenSession())
    //                         assert.isDefined(sessionRecord.getOpenSession())
    //                         done()
    //                     })
    //                 })
    //             })
    //             .catch(done)
    //     })

    //     it('rejects untrusted identity keys', function (done) {
    //         KeyHelper.generateIdentityKeyPair().then(function (newIdentity) {
    //             const builder = new libsignal.SessionBuilder(aliceStore, BOB_ADDRESS)
    //             return builder
    //                 .processPreKey({
    //                     identityKey: newIdentity.pubKey,
    //                     registrationId: 12356,
    //                 })
    //                 .then(function (e) {
    //                     assert.fail('should not be trusted')
    //                 })
    //                 .catch(function (e) {
    //                     assert.strictEqual(e.message, 'Identity key changed')
    //                     done()
    //                 })
    //                 .catch(done)
    //        })
    //    })
    //})
})
