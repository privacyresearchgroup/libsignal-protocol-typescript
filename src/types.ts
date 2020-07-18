/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/explicit-module-boundary-types */
export interface SignalProtocolAddressType {
    readonly name: string
    readonly deviceId: number
    toString: () => string
    equals: (other: SignalProtocolAddressType) => boolean
}

export interface FingerprintGeneratorType {
    createFor: (
        localIdentifier: string,
        localIdentityKey: ArrayBuffer,
        remoteIdentifier: string,
        remoteIdentityKey: ArrayBuffer
    ) => Promise<string>
}

export interface KeyPairType<T = ArrayBuffer> {
    pubKey: T
    privKey: T
}

export interface PreKeyPairType<T = ArrayBuffer> {
    keyId: number
    keyPair: KeyPairType<T>
}

export interface SignedPreKeyPairType<T = ArrayBuffer> extends PreKeyPairType<T> {
    signature: T
}

export interface PreKeyType<T = ArrayBuffer> {
    keyId: number
    publicKey: T
}

export interface SignedPublicPreKeyType<T = ArrayBuffer> extends PreKeyType<T> {
    signature: T
}

// TODO: Make this match reality
export interface RecordType {
    archiveCurrentState: () => void
    deleteAllSessions: () => void
    getOpenSession: () => void
    getSessionByBaseKey: () => void
    getSessions: () => void
    haveOpenSession: () => void
    promoteState: () => void
    serialize: () => void
    updateSessionState: () => void
}

// TODO: any????
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type SessionRecordType = string

export type Stringable = string | ArrayBuffer | Buffer | Uint8Array | number | undefined

export enum Direction {
    SENDING = 1,
    RECEIVING = 2,
}
export interface StorageType {
    getIdentityKeyPair: () => Promise<KeyPairType | undefined>
    getLocalRegistrationId: () => Promise<number | undefined>

    // TODO: direction is unused in test code but probably should be required
    isTrustedIdentity: (identifier: string, identityKey: ArrayBuffer, direction?: Direction) => Promise<boolean>
    saveIdentity: (encodedAddress: string, publicKey: ArrayBuffer, nonblockingApproval?: boolean) => Promise<boolean>

    loadPreKey: (encodedAddress: string | number) => Promise<KeyPairType | undefined>
    storePreKey: (keyId: number | string, keyPair: KeyPairType) => Promise<void>
    removePreKey: (keyId: number | string) => Promise<void>

    storeSession: (encodedAddress: string, record: SessionRecordType) => Promise<void>
    loadSession: (encodedAddress: string) => Promise<SessionRecordType | undefined>

    // This returns a KeyPairType, but note that it's the implenenter's responsibility to validate!
    loadSignedPreKey: (keyId: number | string) => Promise<KeyPairType | undefined>
    storeSignedPreKey: (keyId: number | string, keyPair: KeyPairType) => Promise<void>
    removeSignedPreKey: (keyId: number | string) => Promise<void>
}

export interface CurveType {
    generateKeyPair: () => Promise<KeyPairType>
    createKeyPair: (privKey: ArrayBuffer) => Promise<KeyPairType>
    calculateAgreement: (pubKey: ArrayBuffer, privKey: ArrayBuffer) => Promise<ArrayBuffer>
    verifySignature: (pubKey: ArrayBuffer, msg: ArrayBuffer, sig: ArrayBuffer) => Promise<void>
    calculateSignature: (privKey: ArrayBuffer, message: ArrayBuffer) => ArrayBuffer | Promise<ArrayBuffer>
    validatePubKeyFormat: (buffer: ArrayBuffer) => ArrayBuffer
}

export interface AsyncCurveType {
    generateKeyPair: () => Promise<KeyPairType>
    createKeyPair: (privKey: ArrayBuffer) => Promise<KeyPairType>
    calculateAgreement: (pubKey: ArrayBuffer, privKey: ArrayBuffer) => Promise<ArrayBuffer>
    verifySignature: (pubKey: ArrayBuffer, msg: ArrayBuffer, sig: ArrayBuffer) => Promise<boolean>
    calculateSignature: (privKey: ArrayBuffer, message: ArrayBuffer) => Promise<ArrayBuffer>
}

// Type guards
// TODO check if ArrayBuffer!
export function isKeyPairType(kp: any): kp is KeyPairType {
    return !!(kp?.privKey && kp?.pubKey)
}

export function isPreKeyType(pk: any): pk is PreKeyPairType {
    return typeof pk?.keyId === 'number' && isKeyPairType(pk?.keyPair)
}

export function isSignedPReKeyType(spk: any): spk is SignedPreKeyPairType {
    return spk?.signature && isPreKeyType(spk)
}
