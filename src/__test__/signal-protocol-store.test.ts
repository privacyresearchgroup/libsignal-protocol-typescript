import { SignalProtocolAddress } from '../signal-protocol-address'
import { SignalProtocolStore } from './storage-type'
import * as Internal from '../internal'
import { assertEqualArrayBuffers } from '../__test-utils__/utils'

describe('SignalProtocolStore', function () {
    const store = new SignalProtocolStore()
    const registrationId = 1337
    const identityKey = {
        pubKey: Internal.crypto.getRandomBytes(33),
        privKey: Internal.crypto.getRandomBytes(32),
    }
    beforeAll(async () => {
        store.put('registrationId', registrationId)
        store.put('identityKey', identityKey)
    })
    const keyPairPromise = Internal.crypto.createKeyPair()

    //     testIdentityKeyStore(store, registrationId, identityKey);
    describe('IdentityKeyStore', function () {
        const number = '+5558675309'
        const address = new SignalProtocolAddress('+5558675309', 1)

        describe('getLocalRegistrationId', function () {
            test('retrieves my registration id', async () => {
                const reg = await store.getLocalRegistrationId()
                expect(reg).toBe(registrationId)
            })
        })
        describe('getIdentityKeyPair', function () {
            test('retrieves my identity key', async () => {
                const key = await store.getIdentityKeyPair()

                expect(key).toBeDefined()
                if (key) {
                    // we know we get here by previous assertion
                    assertEqualArrayBuffers(key.pubKey, identityKey.pubKey)
                    assertEqualArrayBuffers(key.privKey, identityKey.privKey)
                }
            })
        })

        describe('saveIdentity', function () {
            test('stores identity keys', async () => {
                const testKey = await keyPairPromise
                await store.saveIdentity(address.toString(), testKey.pubKey)
                const key = await store.loadIdentityKey(number)
                expect(key).toBeDefined()
                if (key) {
                    assertEqualArrayBuffers(key, testKey.pubKey)
                }
            })
        })
        describe('isTrustedIdentity', function () {
            test('returns true if a key is trusted', async () => {
                const testKey = await keyPairPromise
                await store.saveIdentity(address.toString(), testKey.pubKey)
                const trusted = await store.isTrustedIdentity(number, testKey.pubKey)
                expect(trusted).toBeTruthy()
            })

            test('returns false if a key is untrusted', async () => {
                const testKey = await keyPairPromise
                const newIdentity = Internal.crypto.getRandomBytes(33)
                await store.saveIdentity(address.toString(), testKey.pubKey)
                const trusted = await store.isTrustedIdentity(number, newIdentity)
                expect(trusted).toBeFalsy()
            })
        })
    })
    //    testPreKeyStore(store);
    describe('PreKeyStore', function () {
        const number = '+5558675309'

        describe('storePreKey', function () {
            test('stores prekeys', async () => {
                const testKey = await keyPairPromise
                const address = new SignalProtocolAddress(number, 1)
                await store.storePreKey(address.toString(), testKey)
                const key = await store.loadPreKey(address.toString())
                expect(key).toBeDefined()
                if (key) {
                    assertEqualArrayBuffers(key.pubKey, testKey.pubKey)
                    assertEqualArrayBuffers(key.privKey, testKey.privKey)
                }
            })
        })

        describe('loadPreKey', function () {
            test('returns prekeys that exist', async () => {
                const testKey = await keyPairPromise
                const address = new SignalProtocolAddress(number, 1)
                await store.storePreKey(address.toString(), testKey)
                const key = await store.loadPreKey(address.toString())

                expect(key).toBeDefined()
                if (key) {
                    assertEqualArrayBuffers(key.pubKey, testKey.pubKey)
                    assertEqualArrayBuffers(key.privKey, testKey.privKey)
                }
            })
            test('returns undefined for prekeys that do not exist', async () => {
                // eslint-disable-next-line @typescript-eslint/no-unused-vars
                const address = new SignalProtocolAddress(number, 2)
                const key = await store.loadPreKey('2')
                expect(key).toBeUndefined()
            })
        })
        describe('removePreKey', function () {
            test('deletes prekeys', async () => {
                const testKey = await keyPairPromise

                const address = new SignalProtocolAddress(number, 2)
                await store.storePreKey(address.toString(), testKey)
                await store.removePreKey(address.toString())
                const key = await store.loadPreKey(address.toString())
                expect(key).toBeUndefined()
            })
        })
    })
    describe('SignedPreKeyStore', function () {
        describe('storeSignedPreKey', function () {
            test('stores signed prekeys', async () => {
                const testKey = await keyPairPromise
                await store.storeSignedPreKey(3, testKey)
                const key = await store.loadSignedPreKey(3)
                expect(key).toBeDefined()
                if (key) {
                    assertEqualArrayBuffers(key.pubKey, testKey.pubKey)
                    assertEqualArrayBuffers(key.privKey, testKey.privKey)
                }
            })
        })

        describe('loadSignedPreKey', function () {
            test('returns prekeys that exist', async () => {
                const testKey = await keyPairPromise
                await store.storeSignedPreKey(1, testKey)
                const key = await store.loadSignedPreKey(1)
                expect(key).toBeDefined()
                if (key) {
                    assertEqualArrayBuffers(key.pubKey, testKey.pubKey)
                    assertEqualArrayBuffers(key.privKey, testKey.privKey)
                }
            })

            test('returns undefined for prekeys that do not exist', async () => {
                const testKey = await keyPairPromise
                await store.storeSignedPreKey(1, testKey)
                const key = await store.loadSignedPreKey(2)
                expect(key).toBeUndefined()
            })
        })

        describe('removeSignedPreKey', function () {
            test('deletes signed prekeys', async () => {
                const testKey = await keyPairPromise
                await store.storeSignedPreKey(4, testKey)
                await store.removeSignedPreKey(4) //  testKey)
                const key = await store.loadSignedPreKey(4)
                expect(key).toBeUndefined()
            })
        })
    })
    //testSessionStore
    describe('SessionStore', function () {
        const address = new SignalProtocolAddress('+5558675309', 1)
        const number = '+5558675309'

        const testRecord = 'an opaque string'

        describe('storeSession', function () {
            // TODO: this used to store sessions encoded as array buffers, but the SDK
            // always stores them as strings. Changed the tests accordingly
            test('stores sessions -- see comment in code', async () => {
                await store.storeSession(address.toString(), testRecord)
                const record = await store.loadSession(address.toString())
                expect(record).toBeDefined()
                if (record) {
                    expect(testRecord).toStrictEqual(record)
                }
            })
        })
        describe('loadSession', function () {
            test('loadSession returns sessions that exist', async () => {
                const address = new SignalProtocolAddress(number, 1)
                const testRecord = 'an opaque string'
                // const enc = new TextEncoder()
                await store.storeSession(address.toString(), testRecord)
                const record = await store.loadSession(address.toString())
                expect(record).toBeDefined()
                expect(record).toStrictEqual(testRecord)
            })

            test('returns undefined for sessions that do not exist', async () => {
                const address = new SignalProtocolAddress(number, 2)
                const record = await store.loadSession(address.toString())
                expect(record).toBeUndefined()
            })
        })
        describe('removeSession', function () {
            test('deletes sessions', async () => {
                const address = new SignalProtocolAddress(number, 1)
                // const enc = new TextEncoder()
                await store.storeSession(address.toString(), testRecord)
                await store.removeSession(address.toString())
                const record = await store.loadSession(address.toString())
                expect(record).toBeUndefined()
            })
        })
        describe('removeAllSessions', function () {
            test('removes all sessions for a number', async () => {
                const devices = [1, 2, 3].map(function (deviceId) {
                    const address = new SignalProtocolAddress(number, deviceId)
                    return address.toString()
                })
                await devices.forEach(function (encodedNumber) {
                    // const enc = new TextEncoder()

                    store.storeSession(encodedNumber, testRecord + encodedNumber)
                })
                await store.removeAllSessions(number)
                const records = await Promise.all(devices.map(store.loadSession.bind(store)))
                for (const i in records) {
                    expect(records[i]).toBeUndefined()
                }
            })
        })
    })
})
