import { SignalProtocolAddress } from '../signal-protocol-address'
import ByteBuffer from 'bytebuffer'

interface KeyPairType {
    pubKey: ArrayBuffer
    privKey: ArrayBuffer
}

interface PreKeyType {
    keyId: number
    keyPair: KeyPairType
}
type SessionRecordType = ArrayBuffer
interface SignedPreKeyType extends PreKeyType {
    signature: ArrayBuffer
}
// copied toString from util() in the helpers.ts file
function toString(thing: any): string {
    if (typeof thing == 'string') {
        return thing
    }
    return ByteBuffer.wrap(thing).toString('binary')
}

export class SignalProtocolStore {
    private _store: object
    Direction = {
        SENDING: 1,
        RECEIVING: 2,
    }

    constructor() {
        this._store = {}
    }
    //
    get(key: any, defaultValue: any): any {
        if (key === null || key === undefined) throw new Error('Tried to get value for undefined/null key')
        if (key in this._store) {
            return this._store[key]
        } else {
            return defaultValue
        }
    }
    remove(key: any): any {
        if (key === null || key === undefined) throw new Error('Tried to remove value for undefined/null key')
        delete this._store[key]
    }
    put(key: string, value: any): any {
        if (key === undefined || value === undefined || key === null || value === null)
            throw new Error('Tried to store undefined/null')
        this._store[key] = value
    }
    //
    getIdentityKeyPair(): Promise<KeyPairType> {
        return Promise.resolve(this.get('identityKey', undefined))
    }
    getLocalRegistrationId(): Promise<number> {
        return Promise.resolve(this.get('registrationId', undefined))
    }
    isTrustedIdentity(identifier: any, identityKey: ArrayBuffer): Promise<boolean> {
        if (identifier === null || identifier === undefined) {
            throw new Error('tried to check identity key for undefined/null key')
        }
        const trusted = this.get('identityKey' + identifier, undefined)
        if (trusted === undefined) {
            return Promise.resolve(true)
        }
        return Promise.resolve(toString(identityKey) === toString(trusted))
    }
    loadPreKey(keyId: string): Promise<KeyPairType> {
        let res = this.get('25519KeypreKey' + keyId, undefined)
        if (res !== undefined) {
            res = { pubKey: res.pubKey, privKey: res.privKey }
        }
        return Promise.resolve(res)
    }
    loadSession(identifier: string): Promise<SessionRecordType> {
        return Promise.resolve(this.get('session' + identifier, undefined))
    }
    loadSignedPreKey(keyId: number): Promise<KeyPairType> {
        // loadSignedPreKey: function(keyId) {
        let res = this.get('25519KeysignedKey' + keyId, undefined)
        if (res !== undefined) {
            res = { pubKey: res.pubKey, privKey: res.privKey }
        }
        return Promise.resolve(res)
    }
    removePreKey(keyId: string): Promise<void> {
        //    removePreKey: function(keyId) {
        return Promise.resolve(this.remove('25519KeypreKey' + keyId))
    }
    saveIdentity(identifier: string, identityKey: ArrayBuffer): Promise<boolean> {
        //   saveIdentity: function(identifier, identityKey) {
        if (identifier === null || identifier === undefined)
            throw new Error('Tried to put identity key for undefined/null key')

        var address = SignalProtocolAddress.fromString(identifier)

        var existing = this.get('identityKey' + address.getName(), undefined)
        this.put('identityKey' + address.getName(), identityKey)

        if (existing && toString(identityKey) !== toString(existing)) {
            return Promise.resolve(true)
        } else {
            return Promise.resolve(false)
        }
    }
    storeSession(identifier: string, record: any): Promise<void> {
        return Promise.resolve(this.put('session' + identifier, record))
    }
    loadIdentityKey(identifier): Promise<any> {
        if (identifier === null || identifier === undefined)
            throw new Error('Tried to get identity key for undefined/null key')
        return Promise.resolve(this.get('identityKey' + identifier, undefined))
    }
    storePreKey(keyId, keyPair): Promise<void> {
        return Promise.resolve(this.put('25519KeypreKey' + keyId, keyPair))
    }
    storeSignedPreKey(keyId, keyPair): Promise<void> {
        return Promise.resolve(this.put('25519KeysignedKey' + keyId, keyPair))
    }
    removeSignedPreKey(keyId): Promise<void> {
        return Promise.resolve(this.remove('25519KeysignedKey' + keyId))
    }
    removeSession(identifier): Promise<void> {
        return Promise.resolve(this.remove('session' + identifier))
    }
    removeAllSessions(identifier): Promise<void> {
        for (var id in this._store) {
            if (id.startsWith('session' + identifier)) {
                delete this._store[id]
            }
        }
        return Promise.resolve()
    }
}
