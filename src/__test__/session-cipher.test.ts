/* eslint-disable @typescript-eslint/no-non-null-assertion */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { SessionCipher, MessageType } from '../session-cipher'
import { SessionBuilder } from '../session-builder'
import { generateIdentity, generatePreKeyBundle, assertEqualArrayBuffers } from '../__test-utils__/utils'

import { SignalProtocolStore } from './storage-type'
import { SignalProtocolAddress } from '../signal-protocol-address'
import { SessionRecord } from '../session-record'
import { TestVectors } from './testvectors'
import * as Internal from '../internal'
import { KeyPairType } from '../types'
import * as utils from '../helpers'
import {
    PreKeyWhisperMessage,
    PushMessageContent,
    IncomingPushMessageSignal,
    IncomingPushMessageSignal_Type,
    PushMessageContent_Flags,
} from '@privacyresearch/libsignal-protocol-protobuf-ts'

//import { KeyPairType } from '../types'
const tv = TestVectors()
// TODO: import this when Rolfe gets it right
export enum ChainType {
    SENDING = 1,
    RECEIVING = 2,
}
export enum BaseKeyType {
    OURS = 1,
    THEIRS = 2,
}
//--

const store = new SignalProtocolStore()
const registrationId = 1337
const address = new SignalProtocolAddress('foo', 1)
const sessionCipher = new SessionCipher(store, address.toString())

//before(function(done) {
const record = new SessionRecord(registrationId)
const session = {
    registrationId: registrationId,
    currentRatchet: {
        rootKey: new ArrayBuffer(32),
        lastRemoteEphemeralKey: new ArrayBuffer(32),
        previousCounter: 0,
    },
    indexInfo: {
        baseKey: new ArrayBuffer(32),
        baseKeyType: BaseKeyType.OURS,
        remoteIdentityKey: new ArrayBuffer(32),
        closed: -1,
    },
    oldRatchetList: [],
    chains: {},
}
record.updateSessionState(session)
const prep = store.storeSession(address.toString(), record.serialize())

test('getRemoteRegistrationId, when an open record exists, returns a valid registrationId', async () => {
    await prep
    const value = await sessionCipher.getRemoteRegistrationId()
    expect(value).toBe(registrationId)
})

test('getRemoteRegistrationId, when a record does not exist, returns undefined', async () => {
    await prep
    const sessionCipher = new SessionCipher(store, 'bar.1')
    const value = await sessionCipher.getRemoteRegistrationId()
    expect(value).toBeUndefined()
})

test('hasOpenSession returns true', async () => {
    await prep
    const value = await sessionCipher.hasOpenSession()
    expect(value).toBeTruthy()
})

it('hasOpenSession: no open session exists returns false', async () => {
    await prep
    const address = new SignalProtocolAddress('bar', 1)
    const sessionCipher = new SessionCipher(store, address.toString())
    const record = new SessionRecord()
    await store.storeSession(address.toString(), record.serialize())
    const value = await sessionCipher.hasOpenSession()
    expect(value).toBeFalsy()
})

test('hasOpenSession: when there is no session returns false', async () => {
    await prep
    const address = new SignalProtocolAddress('baz', 1)
    const sessionCipher = new SessionCipher(store, address.toString())
    const value = await sessionCipher.hasOpenSession()
    expect(value).toBeFalsy()
})
//----------------------------------------------------------------------------------------------------
async function setupReceiveStep(
    store: SignalProtocolStore,
    data: { [k: string]: any },
    privKeyQueue: ArrayBuffer[]
): Promise<void> {
    if (data.newEphemeralKey !== undefined) {
        privKeyQueue.push(data.newEphemeralKey)
    }

    if (data.ourIdentityKey === undefined) {
        return Promise.resolve()
    }

    const keyPair = await Internal.crypto.createKeyPair(data.ourIdentityKey)
    await store.put('identityKey', keyPair)
    const signedKeyPair = await Internal.crypto.createKeyPair(data.ourSignedPreKey)
    await store.storeSignedPreKey(data.signedPreKeyId, signedKeyPair)
    if (data.ourPreKey !== undefined) {
        const keyPair = await Internal.crypto.createKeyPair(data.ourPreKey)
        store.storePreKey(data.preKeyId, keyPair)
    }
}

function getPaddedMessageLength(messageLength: number): number {
    const messageLengthWithTerminator = messageLength + 1
    let messagePartCount = Math.floor(messageLengthWithTerminator / 160)
    if (messageLengthWithTerminator % 160 !== 0) {
        messagePartCount++
    }
    return messagePartCount * 160
}

function pad(plaintext: ArrayBuffer): ArrayBuffer {
    const paddedPlaintext = new Uint8Array(getPaddedMessageLength(plaintext.byteLength + 1) - 1)
    paddedPlaintext.fill(0)
    paddedPlaintext.set(new Uint8Array(plaintext))
    paddedPlaintext[plaintext.byteLength] = 0x80
    return paddedPlaintext.buffer
}

function unpad(paddedPlaintext: Uint8Array): Uint8Array {
    const ppt = new Uint8Array(paddedPlaintext)
    //paddedPlaintext = new Uint8Array(paddedPlaintext)
    for (let i = ppt.length - 1; i >= 0; i--) {
        if (ppt[i] == 0x80) {
            const plaintext = new Uint8Array(i)
            plaintext.set(ppt.subarray(0, i))
            return plaintext
        } else if (ppt[i] !== 0x00) {
            throw new Error('Invalid padding')
        }
    }
    throw new Error('Invalid data: input empty or all 0x00s')
}

async function doReceiveStep(
    store: SignalProtocolStore,
    data: { [k: string]: any },
    privKeyQueue: Array<any>,
    address: string
): Promise<boolean> {
    await setupReceiveStep(store, data, privKeyQueue)
    const sessionCipher = new SessionCipher(store, address)
    let plaintext: Uint8Array
    //    if (data.type == textsecure.protobuf.IncomingPushMessageSignal.Type.CIPHERTEXT) {
    if (data.type == IncomingPushMessageSignal_Type.CIPHERTEXT) {
        const dWS: Uint8Array = new Uint8Array(await sessionCipher.decryptWhisperMessage(data.message))
        plaintext = await unpad(dWS)
        //    } else if (data.type == textsecure.protobuf.IncomingPushMessageSignal.Type.PREKEY_BUNDLE) {
    } else if (data.type == IncomingPushMessageSignal_Type.PREKEY_BUNDLE) {
        const dPKWS: Uint8Array = new Uint8Array(await sessionCipher.decryptPreKeyWhisperMessage(data.message))
        plaintext = await unpad(dPKWS)
    } else {
        throw new Error('Unknown data type in test vector')
    }

    const content = PushMessageContent.decode(plaintext)
    if (data.expectTerminateSession) {
        if (content.flags == PushMessageContent_Flags.END_SESSION) {
            return true
        } else {
            return false
        }
    }
    return (
        content.body == data.expectedSmsText
        //.catch(function checkException(e) {
        //   if (data.expectException) {
        //       return true
        //   }
        //   throw e
        // })
    )
}

async function setupSendStep(
    store: SignalProtocolStore,
    data: { [k: string]: any },
    privKeyQueue: Array<any>
): Promise<void> {
    if (data.registrationId !== undefined) {
        store.put('registrationId', data.registrationId)
    }
    if (data.ourBaseKey !== undefined) {
        privKeyQueue.push(data.ourBaseKey)
    }
    if (data.ourEphemeralKey !== undefined) {
        privKeyQueue.push(data.ourEphemeralKey)
    }

    if (data.ourIdentityKey !== undefined) {
        const keyPair: KeyPairType = await Internal.crypto.createKeyPair(data.ourIdentityKey)
        store.put('identityKey', keyPair)
    }
    return Promise.resolve()
}

async function doSendStep(
    store: SignalProtocolStore,
    data: { [k: string]: any },
    privKeyQueue: Array<any>,
    address: string
): Promise<boolean> {
    await setupSendStep(store, data, privKeyQueue)

    if (data.getKeys !== undefined) {
        const deviceObject = {
            encodedNumber: address.toString(),
            identityKey: data.getKeys.identityKey,
            preKey: data.getKeys.devices[0].preKey,
            signedPreKey: data.getKeys.devices[0].signedPreKey,
            registrationId: data.getKeys.devices[0].registrationId,
        }
        const builder = new SessionBuilder(store, SignalProtocolAddress.fromString(address))
        await builder.processPreKey(deviceObject)
    }

    const proto = PushMessageContent.fromJSON({})
    if (data.endSession) {
        proto.flags = PushMessageContent_Flags.END_SESSION
    } else {
        proto.body = data.smsText
    }

    const sessionCipher = new SessionCipher(store, address)
    const msg = await sessionCipher.encrypt(pad(utils.toArrayBuffer(proto.body)!))
    //XXX: This should be all we do: isEqual(data.expectedCiphertext, encryptedMsg, false);
    let res: boolean
    if (msg.type === 1) {
        res = utils.isEqual(data.expectedCiphertext, utils.toArrayBuffer(msg.body))
    } else {
        if (new Uint8Array(data.expectedCiphertext)[0] !== msg.body?.charCodeAt(0)) {
            throw new Error('Bad version byte')
        }

        //        const expected = Internal.protobuf.PreKeyWhisperMessage.decode(data.expectedCiphertext.slice(1)).encode()
        //const expected = protobuf.PreKeyWhisperMessage.decode(data.expectedCiphertext.slice(1)).encode()
        const pkwmsg = PreKeyWhisperMessage.decode(data.expectedCiphertext.slice(1))
        const expected = PreKeyWhisperMessage.encode(pkwmsg).finish()

        if (!utils.isEqual(expected, utils.toArrayBuffer(msg.body.substring(1)))) {
            throw new Error('Result does not match expected ciphertext')
        }

        res = true
    }
    if (data.endSession) {
        await sessionCipher.closeOpenSessionForDevice()
        return res
    }
    return res
}

function getDescription(step: { [k: string]: any }): string {
    const direction = step[0]
    const data = step[1]
    if (direction === 'receiveMessage') {
        if (data.expectTerminateSession) {
            return 'receive end session message'
        } else if (data.type === 3) {
            return 'receive prekey message ' + data.expectedSmsText
        } else {
            return 'receive message ' + data.expectedSmsText
        }
    } else if (direction === 'sendMessage') {
        if (data.endSession) {
            return 'send end session message'
        } else if (data.ourIdentityKey) {
            return 'send prekey message ' + data.smsText
        } else {
            return 'send message ' + data.smsText
        }
    }
    return ''
}

//TestVectors.forEach(function (test) {
tv.forEach(function (test) {
    describe(test.name, async () => {
        // function (done) {
        //  this.timeout(20000)

        const privKeyQueue = []
        const origCreateKeyPair = Internal.crypto.createKeyPair

        beforeAll(function () {
            // Shim createKeyPair to return predetermined keys from
            // privKeyQueue instead of random keys.
            Internal.crypto.createKeyPair = function (privKey) {
                if (privKey !== undefined) {
                    return origCreateKeyPair(privKey)
                }
                if (privKeyQueue.length == 0) {
                    throw new Error('Out of private keys')
                } else {
                    const privKey = privKeyQueue.shift()
                    return Internal.crypto.createKeyPair(privKey).then(function (keyPair) {
                        const a = btoa(utils.toString(keyPair.privKey))
                        const b = btoa(utils.toString(privKey))
                        if (utils.toString(keyPair.privKey) != utils.toString(privKey))
                            throw new Error('Failed to rederive private key!')
                        else return keyPair
                    })
                }
            }
        })

        afterAll(function () {
            Internal.crypto.createKeyPair = origCreateKeyPair
            if (privKeyQueue.length != 0) {
                throw new Error('Leftover private keys')
            }
        })

        function describeStep(step) {
            const direction = step[0]
            const data = step[1]
            if (direction === 'receiveMessage') {
                if (data.expectTerminateSession) {
                    return 'receive end session message'
                } else if (data.type === 3) {
                    return 'receive prekey message ' + data.expectedSmsText
                } else {
                    return 'receive message ' + data.expectedSmsText
                }
            } else if (direction === 'sendMessage') {
                if (data.endSession) {
                    return 'send end session message'
                } else if (data.ourIdentityKey) {
                    return 'send prekey message ' + data.smsText
                } else {
                    return 'send message ' + data.smsText
                }
            }
        }

        const store = new SignalProtocolStore()
        const address = SignalProtocolAddress.fromString('SNOWDEN.1')
        test.vectors.forEach(function (step) {
            it(getDescription(step), async () => {
                let doStep

                if (step[0] === 'receiveMessage') {
                    doStep = doReceiveStep
                } else if (step[0] === 'sendMessage') {
                    doStep = doSendStep
                } else {
                    throw new Error('Invalid test')
                }

                await expect(doStep(store, step[1], privKeyQueue, address)).resolves.toBeTruthy() //.then(assert).then(done, done)
            })
        })
    })
})

describe('key changes', function () {
    const ALICE_ADDRESS = new SignalProtocolAddress('+14151111111', 1)
    const BOB_ADDRESS = new SignalProtocolAddress('+14152222222', 1)
    const originalMessage = <ArrayBuffer>utils.toArrayBuffer("L'homme est condamné à être libre")

    const aliceStore = new SignalProtocolStore()

    const bobStore = new SignalProtocolStore()
    const bobPreKeyId = 1337
    const bobSignedKeyId = 1

    //var Curve = libsignal.Curve

    const bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS)

    //TODO should this be beforeAll or beforeEach?
    beforeEach(function (done) {
        Promise.all([aliceStore, bobStore].map(generateIdentity))
            .then(function () {
                return generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId)
            })
            .then(function (preKeyBundle) {
                const builder = new SessionBuilder(aliceStore, BOB_ADDRESS)
                return (
                    builder
                        .processPreKey(preKeyBundle)
                        .then(function () {
                            const aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS)
                            return aliceSessionCipher.encrypt(originalMessage)
                        })
                        .then(function (ciphertext) {
                            return bobSessionCipher.decryptPreKeyWhisperMessage(ciphertext.body!, 'binary')
                        })
                        .then(function () {
                            done()
                        })
                        // })
                        .catch(done)
                )
            })
    })

    describe("When bob's identity changes", function () {
        let messageFromBob: MessageType
        beforeEach(async () => {
            const ciphertext = await bobSessionCipher.encrypt(originalMessage)
            messageFromBob = ciphertext
            await generateIdentity(bobStore)
            const idK = <KeyPairType>bobStore.get('identityKey', undefined)
            const pubK = idK.pubKey
            return aliceStore.saveIdentity(BOB_ADDRESS.toString(), pubK)
        })

        test('alice cannot encrypt with the old session', async () => {
            const aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS)
            await expect(async () => {
                //
                await aliceSessionCipher.encrypt(originalMessage)
            }).rejects.toThrow('Identity key changed')
            // .catch(function (e) {
            //     assert.strictEqual(e.message, 'Identity key changed')
            // })
            // .then(done, done)
        })

        test('alice cannot decrypt from the old session', async () => {
            const aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS)
            await expect(async () => {
                await aliceSessionCipher.decryptWhisperMessage(<string>messageFromBob.body, 'binary')
            }).rejects.toThrow('Identity key changed')
            //                .catch(function (e) {
            //                   assert.strictEqual(e.message, 'Identity key changed')
            //              })
            //             .then(done, done)
        })
    })
})
