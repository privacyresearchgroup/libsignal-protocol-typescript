import { SignalProtocolAddress } from '../signal-protocol-address'
import { SignalProtocolStore } from './storage-type'
import * as Internal from '../internal'
import { assertEqualArrayBuffers } from '../__test-utils__/utils'

function randomBytes(numBytes: number): ArrayBuffer {
    const bytes = Array(numBytes)
    for (let i = 0; i < numBytes; ++i) {
        bytes[i] = Math.floor(256 * Math.random())
    }
    return new Uint8Array(bytes)
}

const store = new SignalProtocolStore()
const registrationId = 1337
const identityKey = {
    pubKey: randomBytes(33),
    privKey: randomBytes(32),
}

store.put('registrationId', registrationId)
store.put('identityKey', identityKey)
//testIdentityKeyStore(store, registrationId, identityKey)
//testPreKeyStore(store)
//testSignedPreKeyStore(store)
//testSessionStore(store)

const keyPairPromise = Internal.crypto.createKeyPair()

const number = '+5558675309'
const address = new SignalProtocolAddress('+5558675309', 1)
//const testKey = await keyPairPromise

test('getLocalRegistrationId retrieves my registration id', async () => {
    const reg = await store.getLocalRegistrationId()
    expect(reg).toBe(registrationId)
})

test('getIdentityKeyPair retrieves my identity key', async () => {
    const key = await store.getIdentityKeyPair()

    expect(key).toBeDefined()
    if (key) {
        // we know we get here by previous assertion
        assertEqualArrayBuffers(key.pubKey, identityKey.pubKey)
        assertEqualArrayBuffers(key.privKey, identityKey.privKey)
    }
})

test('saveIdentity stores identity keys', async () => {
    const testKey = await keyPairPromise
    await store.saveIdentity(address.toString(), testKey.pubKey)
    const key = await store.loadIdentityKey(number)
    expect(key).toBeDefined()
    if (key) {
        assertEqualArrayBuffers(key, testKey.pubKey)
    }
})

test('isTrustedIdentity returns true if a key is trusted', async () => {
    const testKey = await keyPairPromise
    await store.saveIdentity(address.toString(), testKey.pubKey)
    const trusted = await store.isTrustedIdentity(number, testKey.pubKey)
    expect(trusted).toBeTruthy()
})

test('returns false if a key is untrusted', async () => {
    const testKey = await keyPairPromise
    const newIdentity = randomBytes(33)
    await store.saveIdentity(address.toString(), testKey.pubKey)
    const trusted = await store.isTrustedIdentity(number, newIdentity)
    expect(trusted).toBeFalsy()
})
/*
function testPreKeyStore(store) {
    var number = '+5558675309'
    var testKey
    describe('PreKeyStore', function () {
        before(function (done) {
            Internal.crypto
                .createKeyPair()
                .then(function (keyPair) {
                    testKey = keyPair
                })
                .then(done, done)
        })
        */
test('storePreKey stores prekeys', async () => {
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

test('loadPreKey returns prekeys that exist', async () => {
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

test('removePreKey deletes prekeys', async () => {
    const testKey = await keyPairPromise

    const address = new SignalProtocolAddress(number, 2)
    await store.storePreKey(address.toString(), testKey)
    await store.removePreKey(address.toString())
    const key = await store.loadPreKey(address.toString())
    expect(key).toBeUndefined()
})
/*
function testSignedPreKeyStore(store) {
    describe('SignedPreKeyStore', function () {
        var testKey
        before(function (done) {
            Internal.crypto
                .createKeyPair()
                .then(function (keyPair) {
                    testKey = keyPair
                })
                .then(done, done)
        })
        */
test('storeSignedPreKey stores signed prekeys', async () => {
    const testKey = await keyPairPromise
    await store.storeSignedPreKey(3, testKey)
    const key = await store.loadSignedPreKey(3)
    expect(key).toBeDefined()
    if (key) {
        assertEqualArrayBuffers(key.pubKey, testKey.pubKey)
        assertEqualArrayBuffers(key.privKey, testKey.privKey)
    }
})
test('loadSignedPreKey returns prekeys that exist', async () => {
    const testKey = await keyPairPromise
    await store.storeSignedPreKey(1, testKey)
    const key = await store.loadSignedPreKey(1)
    expect(key).toBeDefined()
    if (key) {
        assertEqualArrayBuffers(key.pubKey, testKey.pubKey)
        assertEqualArrayBuffers(key.privKey, testKey.privKey)
    }
})
it('returns undefined for prekeys that do not exist', async () => {
    const testKey = await keyPairPromise
    await store.storeSignedPreKey(1, testKey)
    const key = await store.loadSignedPreKey(2)
    expect(key).toBeUndefined()
})
test('removeSignedPreKey deletes signed prekeys', async () => {
    const testKey = await keyPairPromise
    await store.storeSignedPreKey(4, testKey)
    await store.removeSignedPreKey(4) //  testKey)
    const key = await store.loadSignedPreKey(4)
    expect(key).toBeUndefined()
})

const testRecord = 'an opaque string'

/*
function testSessionStore(store) {
    describe('SessionStore', function () {
        var number = '+5558675309'
        var testRecord = 'an opaque string'
        describe('storeSession', function () {
            var address = new SignalProtocolAddress(number, 1)
            it('stores sessions encoded as strings', function (done) {
                store
                    .storeSession(address.toString(), testRecord)
                    .then(function () {
                        return store.loadSession(address.toString()).then(function (record) {
                            assert.strictEqual(record, testRecord)
                        })
                    })
                    .then(done, done)
            })
            */
test('stores sessions encoded as array buffers', async () => {
    const testRecord = new Uint8Array([1, 2, 3]).buffer
    await store.storeSession(address.toString(), testRecord)
    const record = await store.loadSession(address.toString())
    expect(record).toBeDefined()
    if (record) {
        assertEqualArrayBuffers(testRecord, record)
    }
})
test('loadSession returns sessions that exist', async () => {
    const address = new SignalProtocolAddress(number, 1)
    const testRecord = 'an opaque string'
    const enc = new TextEncoder()
    await store.storeSession(address.toString(), enc.encode(testRecord).buffer)
    const record = await store.loadSession(address.toString())
    expect(record).toBeDefined()
    if (record) {
        assertEqualArrayBuffers(record, enc.encode(testRecord).buffer)
    }
})
test('returns undefined for sessions that do not exist', async () => {
    const address = new SignalProtocolAddress(number, 2)
    const record = await store.loadSession(address.toString())
    expect(record).toBeUndefined()
})
test('removeSession deletes sessions', async () => {
    const address = new SignalProtocolAddress(number, 1)
    const enc = new TextEncoder()
    await store.storeSession(address.toString(), enc.encode(testRecord).buffer)
    await store.removeSession(address.toString())
    const record = await store.loadSession(address.toString())
    expect(record).toBeUndefined()
})
test('removeAllSessions removes all sessions for a number', async () => {
    const devices = [1, 2, 3].map(function (deviceId) {
        const address = new SignalProtocolAddress(number, deviceId)
        return address.toString()
    })
    await devices.forEach(function (encodedNumber) {
        console.log(encodedNumber)
        const enc = new TextEncoder()

        store.storeSession(encodedNumber, enc.encode(testRecord + encodedNumber).buffer)
    })
    await store.removeAllSessions(number)
    const records = await Promise.all(devices.map(store.loadSession.bind(store)))
    for (const i in records) {
        expect(records[i]).toBeUndefined()
    }
})
