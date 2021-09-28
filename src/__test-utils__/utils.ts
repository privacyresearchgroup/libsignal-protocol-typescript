import { DeviceType } from '..'
import { KeyHelper } from '../key-helper'
import { SignalProtocolStore } from '../__test__/storage-type'

export function hexToArrayBuffer(str: string): ArrayBuffer {
    const ret = new ArrayBuffer(str.length / 2)
    const array = new Uint8Array(ret)
    for (let i = 0; i < str.length / 2; i++) array[i] = parseInt(str.substr(i * 2, 2), 16)
    return ret
}

export function assertEqualArrayBuffers(ab1: ArrayBuffer, ab2: ArrayBuffer): void {
    const a1 = new Uint8Array(ab1)
    const a2 = new Uint8Array(ab2)
    expect(a1.length).toBe(a2.length)
    for (let i = 0; i < a1.length; ++i) {
        expect(a1[i]).toBe(a2[i])
    }
}

export function assertEqualUint8Arrays(a1: Uint8Array, a2: Uint8Array): void {
    expect(a1.length).toBe(a2.length)
    for (let i = 0; i < a1.length; ++i) {
        expect(a1[i]).toBe(a2[i])
    }
}

export async function generateIdentity(store: SignalProtocolStore): Promise<void> {
    return Promise.all([KeyHelper.generateIdentityKeyPair(), KeyHelper.generateRegistrationId()]).then(function (
        result
    ) {
        store.put('identityKey', result[0])
        store.put('registrationId', result[1])
    })
}

export async function generatePreKeyBundle(
    store: SignalProtocolStore,
    preKeyId: number,
    signedPreKeyId: number
): Promise<DeviceType<ArrayBuffer>> {
    return Promise.all([store.getIdentityKeyPair(), store.getLocalRegistrationId()]).then(function (result) {
        const identity = result[0]
        const registrationId = result[1]

        return Promise.all([
            KeyHelper.generatePreKey(preKeyId),
            // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
            KeyHelper.generateSignedPreKey(identity!, signedPreKeyId),
        ]).then(function (keys) {
            const preKey = keys[0]
            const signedPreKey = keys[1]

            store.storePreKey(preKeyId, preKey.keyPair)
            store.storeSignedPreKey(signedPreKeyId, signedPreKey.keyPair)

            return {
                // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
                identityKey: identity!.pubKey,
                registrationId: registrationId,
                preKey: {
                    keyId: preKeyId,
                    publicKey: preKey.keyPair.pubKey,
                },
                signedPreKey: {
                    keyId: signedPreKeyId,
                    publicKey: signedPreKey.keyPair.pubKey,
                    signature: signedPreKey.signature,
                },
            }
        })
    })
}
